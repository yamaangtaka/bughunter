<?php
/**
 * Reporte anónimo de una reparación que no salió.
 *
 * Va a pasar muchas veces: el análisis es correcto, el arreglo no se puede
 * aplicar, y el caso muere ahí. Este archivo arma el expediente de ese caso
 * para que la persona pueda VERLO entero y descargarlo, que es la misma regla
 * que rige todo lo demás del plugin: primero se enseña, después se decide.
 *
 * ESTA EDICIÓN NO ENVÍA NADA. El reporte se arma aquí y se queda aquí; el
 * transporte que existía se retiró junto con su manejador AJAX. Si el dueño
 * quiere hacérnoslo llegar, descarga el texto y lo manda él, por el medio que
 * prefiera. No hay ninguna petición de salida en este archivo.
 *
 * Aun así el reporte se anonimiza como si fuera a viajar, porque va a acabar
 * en manos de alguien: se quitan el dominio del sitio, las rutas absolutas,
 * los nombres de usuario, las claves, los correos, las IPs escritas en los
 * registros, el prefijo de la base de datos y el código fuente. Queda la forma
 * del fallo: versiones, fase donde se atoró, mensaje del error y consumo.
 *
 * ---------------------------------------------------------------------
 * DATO SENSIBLE - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Reúne en un solo texto el expediente de un caso que no se supo reparar.
 *
 * POR QUE EXISTE:  Es la forma de no quedarnos ciegos cuando el dueño decide contarnos qué pasó. Por eso la anonimización es IRREVERSIBLE y total: sin dominio, sin rutas del servidor, sin nombres de plugins del cliente, sin claves.
 *
 * SI LO RECORTAS:  No le devuelvas la capacidad de enviar. Se retiró a propósito y el readme de esta edición lo promete.
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

/**
 * Class ABH_Report
 */
class ABH_Report {

	/**
	 * Versión del formato. Si cambia la forma del reporte, cambia esto: quien
	 * lo reciba tiene que poder saber qué está leyendo sin adivinar.
	 */
	const FORMATO = 1;

	/**
	 * Destino por defecto. En esta edición nada lo usa para enviar —no hay
	 * envío—; sólo sobrevive para que destino() pueda responder si hay o no un
	 * destino configurado, que es lo que la pantalla consulta antes de ofrecer
	 * la descarga. Queda vacío a propósito.
	 */
	const DESTINO = '';

	/**
	 * Topes. Un reporte que no cabe no se guarda entero: se recorta y se dice.
	 */
	const MAX_MENSAJE = 2000;
	const MAX_EVENTO  = 1000;
	const MAX_EVENTOS = 120;

	/**
	 * Marca que sustituye cualquier cosa identificable.
	 */
	const MARCA = '[anonimizado]';


	/**
	 * Destino validado, o cadena vacía.
	 *
	 * @return string
	 */
	public static function destino() {
		if ( ! ABH_Edition::has_commercial_services() ) {
			return '';
		}
		$url = defined( 'ABH_REPORT_URL' ) ? (string) constant( 'ABH_REPORT_URL' ) : self::DESTINO;
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$limpia = esc_url_raw( $url, array( 'https' ) );
		if ( '' === $limpia || 0 !== strpos( $limpia, 'https://' ) ) {
			return '';
		}
		return $limpia;
	}


	/**
	 * Quita del texto todo lo que señala a ESTE sitio y a esta persona.
	 *
	 * El redactor de ABH_Privacy ya cubre secretos, correos, IPs y las rutas
	 * raíz de WordPress, pero es reversible a propósito: guarda el mapa para
	 * poder devolver el original. Aquí el mapa se tira. Lo que sale de esta
	 * función no se puede deshacer, ni por nosotros.
	 *
	 * @param string $texto Texto a limpiar.
	 * @return string
	 */
	public static function anonimizar( $texto ) {
		$texto = (string) $texto;
		if ( '' === $texto ) {
			return '';
		}

		// 1. El redactor de siempre. El estado se descarta al salir del ámbito.
		if ( class_exists( 'ABH_Privacy' ) ) {
			$estado = ABH_Privacy::state();
			$texto  = ABH_Privacy::redact( $texto, $estado );
			unset( $estado );
		}

		// 2. El dominio del sitio, en todas sus formas.
		$hosts = array();
		foreach ( array( 'home_url', 'site_url', 'network_home_url', 'network_site_url' ) as $fn ) {
			if ( ! function_exists( $fn ) ) {
				continue;
			}
			$host = wp_parse_url( call_user_func( $fn ), PHP_URL_HOST );
			if ( is_string( $host ) && '' !== $host ) {
				$hosts[] = $host;
				$hosts[] = preg_replace( '/^www\./i', '', $host );
				$hosts[] = 'www.' . preg_replace( '/^www\./i', '', $host );
			}
		}
		$hosts = array_values( array_unique( array_filter( $hosts, 'strlen' ) ) );
		usort( $hosts, static function ( $a, $b ) { return strlen( $b ) - strlen( $a ); } );
		foreach ( $hosts as $host ) {
			$texto = str_ireplace( $host, self::MARCA, $texto );
		}

		// 3. Carpetas de usuario del servidor: /home/loquesea, /Users/loquesea,
		// /var/www/loquesea. El nombre de la carpeta suele ser el del cliente.
		$texto = preg_replace( '#/(?:home|home\d+|Users|var/www)/[^/\s"\'<>]+#i', self::MARCA, $texto );

		// 4. Cualquier ruta absoluta que quede antes de una carpeta de
		// WordPress. Lo útil para depurar es «wp-content/plugins/x/y.php», no
		// dónde vive eso en el disco de nadie.
		$texto = preg_replace( '#[A-Za-z]?:?[/\\\\][^\s"\'<>]*?(wp-content|wp-includes|wp-admin)[/\\\\]#i', '$1/', $texto );

		// 5. El prefijo de tablas: revela convenciones del hospedaje y a veces
		// el nombre del proyecto.
		global $wpdb;
		if ( isset( $wpdb->prefix ) && strlen( (string) $wpdb->prefix ) > 2 && 'wp_' !== $wpdb->prefix ) {
			$texto = str_replace( (string) $wpdb->prefix, 'wp_', $texto );
		}

		// 6. Los nombres que puso el cliente.
		$texto = self::despersonalizar_rutas( $texto );

		return $texto;
	}


	/**
	 * Borra los nombres propios de las rutas, conservando su forma.
	 *
	 * Una ruta como wp-content/plugins/acme-corp-crm/inc/class-facturas.php no
	 * lleva el dominio ni la ruta del servidor, y aun así dice quién es el
	 * cliente: el slug del plugin lo puso él, y el nombre del archivo también.
	 * Por eso no basta con quitar el host.
	 *
	 * Lo que se conserva es lo que sirve para saber dónde se atora ESTE motor:
	 * en qué área del sitio ocurrió, a qué profundidad y con qué extensión.
	 * Lo que se pierde es a quién pertenece. El núcleo de WordPress es la
	 * excepción: wp-includes y wp-admin son nombres de WordPress, no de nadie,
	 * y ahí el nombre real vale más que el hueco.
	 *
	 * @param string $texto Texto con rutas dentro.
	 * @return string
	 */
	public static function despersonalizar_rutas( $texto ) {
		return preg_replace_callback(
			// Sin \b delante: el redactor deja marcadores que terminan en «_», y
			// un límite de palabra no salta entre «_» y «w». Ahí se colaba la
			// ruta entera con el nombre del cliente dentro.
			'#wp-content/(plugins|themes|mu-plugins|uploads)/([^\s"\'<>:,;)]+)#i',
			static function ( $m ) {
				$area   = strtolower( $m[1] );
				$partes = explode( '/', trim( $m[2], '/' ) );
				$total  = count( $partes );
				$fuera  = array( 'wp-content/' . $area );

				foreach ( $partes as $i => $parte ) {
					if ( $i === $total - 1 && false !== strpos( $parte, '.' ) ) {
						// Es el archivo: se conserva la extensión, no el nombre.
						$ext     = strtolower( pathinfo( $parte, PATHINFO_EXTENSION ) );
						$fuera[] = '‹file›' . ( '' !== $ext ? '.' . $ext : '' );
						continue;
					}
					if ( 0 === $i ) {
						$fuera[] = 'plugins' === $area ? '‹plugin›' : ( 'themes' === $area ? '‹theme›' : '‹folder›' );
						continue;
					}
					$fuera[] = '‹folder›';
				}

				return implode( '/', $fuera );
			},
			(string) $texto
		);
	}


	/**
	 * La rama de una versión: 8.2.20 → 8.2, 6.8.1 → 6.8.
	 *
	 * @param string $v Versión completa.
	 * @return string
	 */
	private static function rama( $v ) {
		$v = trim( (string) $v );
		if ( '' === $v ) {
			return '';
		}
		$p = explode( '.', $v );
		return isset( $p[1] ) ? $p[0] . '.' . preg_replace( '/[^0-9].*$/', '', $p[1] ) : $p[0];
	}


	/**
	 * Recorta sin mentir: si sobró texto, lo dice.
	 *
	 * @param string $texto Texto.
	 * @param int    $max   Largo máximo.
	 * @return string
	 */
	private static function recortar( $texto, $max ) {
		$texto = (string) $texto;
		if ( strlen( $texto ) <= $max ) {
			return $texto;
		}
		return substr( $texto, 0, $max ) . ' […recortado]';
	}


	/**
	 * Arma el reporte.
	 *
	 * @param array  $job     Trabajo de THOTH, tal como lo guarda ABH_Thoth_AI.
	 * @param array  $eventos Eventos de la consola tal como los pinta el navegador.
	 * @param string $motivo  Por qué no se aplicó nada.
	 * @return array
	 */
	public static function build( $job, $eventos = array(), $motivo = '' ) {
		$job     = is_array( $job ) ? $job : array();
		$inc     = isset( $job['incident'] ) && is_array( $job['incident'] ) ? $job['incident'] : array();
		$uso     = isset( $job['usage'] ) && is_array( $job['usage'] ) ? $job['usage'] : array();
		$ajustes = class_exists( 'ABH_Router' ) ? ABH_Router::settings() : array();

		$reporte = array(
			'formato' => self::FORMATO,
			// Identificador del reporte, no de la instalación: se genera aquí y
			// no se guarda. Dos reportes del mismo sitio no se pueden enlazar.
			'id'      => 'r-' . substr( md5( uniqid( 'abh', true ) ), 0, 12 ),
			'build'   => defined( 'ABH_VERSION' ) ? ABH_VERSION : '',
			// Versiones a dos cifras. La versión exacta de PHP más la exacta de
			// WordPress más el idioma forman una huella fina de más; para saber
			// dónde se atora el motor basta la rama.
			'php'     => self::rama( PHP_VERSION ),
			'wp'      => self::rama( function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : '' ),
			'so'      => defined( 'PHP_OS_FAMILY' ) ? PHP_OS_FAMILY : PHP_OS,
			'idioma'  => function_exists( 'get_locale' ) ? get_locale() : '',
			'motor'   => array(
				// El proveedor y el modelo sirven para reproducir el fallo. La
				// clave no aparece aquí ni puede: no se lee en esta clase.
				'proveedor' => isset( $ajustes['provider'] ) ? (string) $ajustes['provider'] : '',
				// Este reporte sale de la instalación. Un secreto guardado por
				// error en «Modelo» no puede viajar dentro de él.
				'modelo'    => ABH_Privacy::mask_if_secret( isset( $ajustes['model'] ) ? (string) $ajustes['model'] : '' ),
			),
			'estado'  => isset( $job['state'] ) ? (string) $job['state'] : '',
			'motivo'  => self::recortar( self::anonimizar( $motivo ), self::MAX_MENSAJE ),
		);

		$reporte['incidencia'] = array(
			'codigo'   => isset( $inc['code'] ) ? (string) $inc['code'] : '',
			'tipo'     => isset( $inc['type'] ) ? (string) $inc['type'] : '',
			'mensaje'  => self::recortar( self::anonimizar( isset( $inc['message'] ) ? $inc['message'] : ( isset( $inc['short'] ) ? $inc['short'] : '' ) ), self::MAX_MENSAJE ),
			'rel_path' => self::anonimizar( isset( $inc['rel_path'] ) ? $inc['rel_path'] : '' ),
			'linea'    => isset( $inc['line'] ) ? (int) $inc['line'] : 0,
		);

		// Los veredictos de la cadena, que es donde suele estar la respuesta a
		// «por qué se atoró»: qué dijo cada uno y con qué instrucciones salió.
		$reporte['cadena'] = array();
		foreach ( array( 'analysis', 'challenge', 'verdict' ) as $etapa ) {
			if ( empty( $job[ $etapa ] ) || ! is_array( $job[ $etapa ] ) ) {
				continue;
			}
			$trozo = array();
			foreach ( array( 'verdict', 'root_cause', 'reason', 'propuesta', 'fix_hint', 'repair_allowed' ) as $campo ) {
				if ( ! isset( $job[ $etapa ][ $campo ] ) ) {
					continue;
				}
				$valor = $job[ $etapa ][ $campo ];
				if ( is_bool( $valor ) ) {
					$trozo[ $campo ] = $valor;
					continue;
				}
				if ( is_scalar( $valor ) ) {
					$trozo[ $campo ] = self::recortar( self::anonimizar( (string) $valor ), self::MAX_MENSAJE );
				}
			}
			if ( ! empty( $trozo ) ) {
				$reporte['cadena'][ $etapa ] = $trozo;
			}
		}

		// El motivo exacto del rechazo, con código estable. Sin esto, del otro
		// lado solo se ve «no se pudo» y no si falló el modelo, el formato, el
		// alcance o el lint.
		if ( ! empty( $job['failure'] ) && is_array( $job['failure'] ) ) {
			$reporte['fallo'] = array(
				'codigo'      => isset( $job['failure']['codigo'] ) ? (string) $job['failure']['codigo'] : '',
				'etapa'       => isset( $job['failure']['stage'] ) ? (string) $job['failure']['stage'] : '',
				'reintentado' => ! empty( $job['reintento_sin_condiciones'] ),
			);
		}

		$reporte['uso'] = array(
			'in'    => isset( $uso['in'] ) ? (int) $uso['in'] : 0,
			'out'   => isset( $uso['out'] ) ? (int) $uso['out'] : 0,
			'calls' => isset( $job['calls'] ) ? (int) $job['calls'] : 0,
		);

		$reporte['consola'] = self::consola( $eventos );

		// Último cinturón: si algo se coló con la forma de una ruta absoluta o
		// de un dominio, no sale de aquí.
		return self::barrido( $reporte );
	}


	/**
	 * Los eventos de la consola, anonimizados y acotados.
	 *
	 * @param array $eventos Eventos.
	 * @return array
	 */
	private static function consola( $eventos ) {
		$out = array();
		foreach ( array_slice( (array) $eventos, 0, self::MAX_EVENTOS ) as $e ) {
			if ( ! is_array( $e ) ) {
				continue;
			}
			$linea = array(
				'tipo'   => isset( $e['type'] ) ? sanitize_key( (string) $e['type'] ) : 'info',
				'titulo' => self::recortar( self::anonimizar( wp_strip_all_tags( isset( $e['title'] ) ? $e['title'] : '' ) ), self::MAX_EVENTO ),
			);
			if ( ! empty( $e['detail'] ) ) {
				$linea['detalle'] = self::recortar( self::anonimizar( wp_strip_all_tags( (string) $e['detail'] ) ), self::MAX_EVENTO );
			}
			$out[] = $linea;
		}
		return $out;
	}


	/**
	 * Repasa el reporte ya armado y borra lo que huela a identidad.
	 *
	 * Existe porque la anonimización campo por campo se puede olvidar de un
	 * campo nuevo. Esto pasa por TODAS las cadenas del arreglo, vengan de donde
	 * vengan, y es lo último que corre antes de que el reporte exista.
	 *
	 * @param array $datos Reporte.
	 * @return array
	 */
	public static function barrido( $datos ) {
		foreach ( $datos as $k => $v ) {
			if ( is_array( $v ) ) {
				$datos[ $k ] = self::barrido( $v );
				continue;
			}
			if ( is_string( $v ) && '' !== $v ) {
				$datos[ $k ] = self::anonimizar( $v );
			}
		}
		return $datos;
	}


	/**
	 * El reporte como texto, para verlo antes de mandarlo o para guardarlo.
	 *
	 * @param array $reporte Reporte.
	 * @return string
	 */
	public static function json( $reporte ) {
		$texto = wp_json_encode( $reporte, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		return false === $texto ? '' : $texto;
	}


	// RETIRADO A PROPÓSITO: send(). Era el único punto de todo el árbol capaz de
	// mandar un reporte fuera de la instalación, y su único invocador era un
	// manejador AJAX que jamás se registró. Esta edición promete en el readme
	// que no manda reportes a ningún servicio externo; la forma segura de
	// cumplir una promesa así no es dejar el transporte apagado, es no tenerlo.
	// La clase se queda con lo que sirve aquí: armar el reporte, anonimizarlo
	// sin vuelta atrás y convertirlo a texto para verlo o descargarlo. Con él se
	// fue la constante MAX_BYTES, que sólo acotaba el cuerpo de la petición.
	// No lo reintroduzcas.
}
