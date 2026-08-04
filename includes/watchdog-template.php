<?php
/**
 * Plugin Name: AI Bug Hunter Witness
 * Description: Records the fatal errors that take a request down before WordPress gets to log them. It only watches: it does not repair, it does not write files and it does not display anything.
 * Version:     1
 * Author:      AI Bug Hunter
 *
 * ESTE ARCHIVO ES UNA PLANTILLA. Se copia tal cual a wp-content/mu-plugins/.
 *
 * La cabecera va en inglés a propósito. WordPress lee las cabeceras de los
 * mu-plugins antes de que exista ningún dominio de texto, así que un
 * «Plugin Name» en español se queda en español para siempre en Plugins >
 * Imprescindibles, sin traducción posible.
 *
 * Y ese «Plugin Name» hace doble función: es la marca por la que ABH_Watchdog
 * y uninstall.php reconocen que este archivo es suyo. Si lo cambias, cambia
 * también los dos sitios que lo buscan, y deja el literal anterior aceptado
 * para no dejar huérfanas las instalaciones que ya lo tienen en disco.
 *
 * Los mu-plugins cargan antes que todo y no se pueden desactivar desde el
 * panel. Eso resuelve una paradoja: el plugin que repara sitios rotos vive
 * dentro del sitio roto, así que cuanto peor está el sitio, menos disponible
 * está la herramienta. Este testigo sí sobrevive, y ve el fatal que el plugin
 * principal no llega a ver.
 *
 * Reglas que se impone a sí mismo, porque corre en CADA petición del sitio,
 * incluida la portada, y un fallo aquí convertiría un sitio roto en un sitio
 * que no arranca:
 *
 *   1. Nunca imprime nada. Ni un byte, ni siquiera al fallar.
 *   2. Nunca lanza. Todo va envuelto y cualquier problema se traga en silencio.
 *   3. No depende de ninguna clase del plugin principal. Si lo desinstalan,
 *      este archivo queda inerte, no roto.
 *   4. Cero consultas a la base de datos cuando la petición fue bien.
 *   5. Nunca guarda rutas absolutas del servidor: solo relativas.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Se carga como mu-plugin, antes que WordPress entero.
 *
 * POR QUE EXISTE:  Es lo único que sigue vivo cuando el sitio se cae. Por eso no puede depender de nada.
 *
 * SI LO RECORTAS:  No revela información, no expone endpoints y no se puede penetrar. Si alguien le añade una superficie, deja de ser un testigo y pasa a ser una entrada.
 *
 * AI Bug Hunter es una herramienta de acceso tipo root al sitio, pensada
 * para superadministradores y agencias que entienden el riesgo. Lo que nos
 * protege no es quitarnos capacidades: es declararlas, avisar en todas las
 * pantallas y exigir confirmación escrita en lo grave.
 * ---------------------------------------------------------------------
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Cargado dos veces (copia duplicada, orden raro): no se registra de nuevo.
if ( defined( 'ABH_WATCHDOG_VERSION' ) ) {
	return;
}
define( 'ABH_WATCHDOG_VERSION', 1 );
define( 'ABH_WATCHDOG_OPTION', 'abh_watchdog_fatals' );

/**
 * Tipos de error que matan la petición. Los demás no son asunto del testigo.
 *
 * @return array
 */
function abh_watchdog_fatal_types() {
	return array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR );
}

/**
 * Quita del texto cualquier ruta absoluta del servidor.
 *
 * Un mensaje de PHP suele traer la ruta completa: /home/cliente/dominio/...
 * Eso le describe la estructura del servidor a quien lo lea, así que se recorta
 * antes de guardarlo. Guardar de menos nunca le ha hecho daño a nadie.
 *
 * @param string $texto Mensaje original.
 * @return string
 */
function abh_watchdog_redact( $texto ) {
	$texto = (string) $texto;
	$raiz  = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
	$padre = dirname( $raiz );

	foreach ( array( $raiz . '/', $raiz, $padre . '/', $padre ) as $prefijo ) {
		if ( '' !== $prefijo && '/' !== $prefijo ) {
			$texto = str_replace( $prefijo, '', $texto );
			$texto = str_replace( str_replace( '/', '\\', $prefijo ), '', $texto );
		}
	}
	// Cualquier resto de ruta absoluta que se haya escapado.
	$texto = preg_replace( '#/(?:home|var|srv|usr|opt|www|Users)/[^\s\'"):]+#', '[path]', $texto );
	// Fuera caracteres de control: la opción es texto plano, no un canal.
	$texto = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', (string) $texto );

	return function_exists( 'mb_substr' ) ? mb_substr( $texto, 0, 300 ) : substr( $texto, 0, 300 );
}

/**
 * Convierte una ruta absoluta en relativa a la instalación.
 *
 * @param string $abs Ruta.
 * @return string
 */
function abh_watchdog_relative( $abs ) {
	$abs  = str_replace( '\\', '/', (string) $abs );
	$raiz = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/';
	if ( 0 === strpos( $abs, $raiz ) ) {
		$abs = substr( $abs, strlen( $raiz ) );
	}
	$abs = preg_replace( '/[\x00-\x1F\x7F]/', '', (string) $abs );
	return substr( $abs, 0, 200 );
}

/**
 * Anota el fatal, si lo hubo.
 *
 * @return void
 */
function abh_watchdog_shutdown() {
	// Todo el cuerpo va protegido: el testigo jamás puede empeorar la avería.
	try {
		$e = error_get_last();
		if ( ! is_array( $e ) || ! isset( $e['type'], $e['file'], $e['line'] ) ) {
			return;
		}
		if ( ! in_array( (int) $e['type'], abh_watchdog_fatal_types(), true ) ) {
			return;
		}
		// Una petición sana no pasa de aquí: sin fatal, ni una sola consulta.
		if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}

		$rel   = abh_watchdog_relative( $e['file'] );
		$linea = (int) $e['line'];
		$msg   = abh_watchdog_redact( isset( $e['message'] ) ? $e['message'] : '' );
		$firma = md5( (int) $e['type'] . '|' . $rel . '|' . $linea );
		$ahora = time();

		$libro = get_option( ABH_WATCHDOG_OPTION, array() );
		if ( ! is_array( $libro ) ) {
			$libro = array();
		}

		// Freno anti-inundación: alguien puede martillear una URL que revienta.
		// Ya se sabe que sigue cayendo; no hace falta escribirlo cada vez.
		if ( isset( $libro[ $firma ]['last'] ) && ( $ahora - (int) $libro[ $firma ]['last'] ) < 60 ) {
			return;
		}

		if ( isset( $libro[ $firma ] ) ) {
			$libro[ $firma ]['last']  = $ahora;
			$libro[ $firma ]['count'] = min( 999999, (int) $libro[ $firma ]['count'] + 1 );
		} else {
			$libro[ $firma ] = array(
				'kind'  => (int) $e['type'],
				'rel'   => $rel,
				'line'  => $linea,
				'msg'   => $msg,
				'first' => $ahora,
				'last'  => $ahora,
				'count' => 1,
			);
		}

		// Tope duro. Si sobran, se va la que lleva más tiempo sin verse.
		if ( count( $libro ) > 20 ) {
			uasort(
				$libro,
				function ( $a, $b ) {
					return (int) $b['last'] - (int) $a['last'];
				}
			);
			$libro = array_slice( $libro, 0, 20, true );
		}

		// autoload en no: esta opción no debe cargarse en cada petición.
		update_option( ABH_WATCHDOG_OPTION, $libro, false );
	} catch ( Throwable $t ) {
		// Silencio deliberado. Un testigo que grita estropea la escena.
	}
}

register_shutdown_function( 'abh_watchdog_shutdown' );
