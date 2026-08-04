<?php
/**
 * Instalación y lectura del testigo (mu-plugin).
 *
 * El testigo es un archivo diminuto en wp-content/mu-plugins/ que sobrevive a
 * un sitio caído y anota el error fatal que lo tumbó. Esta clase lo instala, lo
 * retira y lee lo que anotó. Nada de esto corre en el testigo: allí no puede
 * haber dependencias.
 *
 * Lo que se instala es un archivo que se ejecuta en TODAS las peticiones del
 * sitio, incluida la portada. Por eso la instalación es explícita, se verifica
 * por huella, y se niega a pisar un archivo que no sea suyo.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Instala un mu-plugin que se carga antes que todo lo demás.
 *
 * POR QUE EXISTE:  Es lo único que puede anotar un error fatal cuando el propio plugin está apagado. Sin él, el caso más grave —el sitio caído— es justo el que no se puede diagnosticar.
 *
 * SI LO RECORTAS:  Quitarlo deja ciego al vigilante. Lo correcto es avisar de que sigue instalado, no retirarlo.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- The optional witness is a local drop-in installed atomically after ownership and collision checks.

/**
 * Class ABH_Watchdog
 */
class ABH_Watchdog {

	/**
	 * Nombre del archivo dentro de mu-plugins.
	 *
	 * Los mu-plugins solo se cargan si están sueltos en esa carpeta: dentro de
	 * un subdirectorio, WordPress no los mira.
	 */
	const FILENAME = 'abh-watchdog.php';

	/**
	 * Opción donde el testigo deja lo que vio.
	 */
	const OPTION = 'abh_watchdog_fatals';

	/**
	 * Carpeta de mu-plugins.
	 *
	 * @return string
	 */
	public static function dir() {
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		return rtrim( wp_normalize_path( $dir ), '/' );
	}

	/**
	 * Ruta destino del testigo.
	 *
	 * @return string
	 */
	public static function path() {
		return self::dir() . '/' . self::FILENAME;
	}

	/**
	 * Plantilla que se copia, tal cual viene en el paquete.
	 *
	 * @return string|false
	 */
	public static function template() {
		$src = ABH_DIR . 'includes/watchdog-template.php';
		if ( ! is_readable( $src ) ) {
			return false;
		}
		$cuerpo = @file_get_contents( $src );
		return ( false === $cuerpo || '' === $cuerpo ) ? false : $cuerpo;
	}

	/**
	 * Estado del testigo en esta instalación.
	 *
	 * @return array
	 */
	public static function status() {
		$path = self::path();
		$out  = array(
			'installed' => false,
			'ours'      => false,
			'current'   => false,
			'writable'  => is_dir( self::dir() ) ? is_writable( self::dir() ) : is_writable( dirname( self::dir() ) ),
			'path'      => str_replace( rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/', '', $path ),
			'active'    => defined( 'ABH_WATCHDOG_VERSION' ),
			'foreign'   => false,
			'partial'   => false,
		);
		if ( ! file_exists( $path ) ) {
			return $out;
		}
		$out['installed'] = true;

		$actual = @file_get_contents( $path );
		if ( false === $actual ) {
			return $out;
		}
		// «Nuestro» se decide por una marca inequívoca del propio archivo, no
		// por el nombre: alguien podría tener otro archivo llamado igual.
		//
		// Se aceptan DOS marcas y las dos hacen falta. La actual, «AI Bug Hunter
		// Witness», y la heredada en español, «AI Bug Hunter · Testigo», que es
		// la que quedó grabada en el disco de todas las instalaciones anteriores
		// a traducir la cabecera. Un mu-plugin no se puede traducir por dominio
		// de texto, así que la cabecera tuvo que cambiar de idioma; si al hacerlo
		// dejásemos de reconocer el literal viejo, esas instalaciones verían su
		// propio testigo como archivo ajeno: no se actualizaría, no se retiraría
		// al desinstalar y se quedaría corriendo en cada petición para siempre.
		// NO borres el literal heredado.
		$plantilla   = self::template();
		$out['ours'] = (
			false !== strpos( $actual, 'ABH_WATCHDOG_OPTION' )
			&& (
				false !== strpos( $actual, 'AI Bug Hunter Witness' )
				|| false !== strpos( $actual, 'AI Bug Hunter · Testigo' )
			)
		);
		// Un testigo NUESTRO que se quedó a medio escribir suele perder las
		// marcas —la segunda vive por la mitad del archivo— y hasta ahora se
		// clasificaba como ajeno: ni se pisaba ni se retiraba, así que el único
		// arreglo era por FTP mientras el sitio entero estaba caído. Un prefijo
		// exacto de la plantilla es nuestro y de nadie más, así que se reconoce
		// aparte y se deja reparar. Lo que no es un prefijo sigue siendo ajeno.
		$out['partial'] = ( false !== $plantilla && self::is_partial_copy( $actual, $plantilla ) );
		if ( $out['partial'] ) {
			$out['ours'] = true;
		}
		if ( ! $out['ours'] ) {
			$out['foreign'] = true;
			return $out;
		}
		$out['current'] = ( false !== $plantilla && ! $out['partial'] && hash_equals( hash( 'sha256', $plantilla ), hash( 'sha256', $actual ) ) );
		return $out;
	}

	/**
	 * ¿Lo que hay en disco es un testigo nuestro que se quedó a medias?
	 *
	 * Una escritura corta —disco lleno, cuota agotada, filesystem de red— deja
	 * en disco los primeros bytes de la plantilla y nada más: un prefijo exacto
	 * y más corto. Ningún archivo de otra persona empieza por nuestra cabecera
	 * entera y se corta justo dentro de ella, así que este es el único caso en
	 * el que se puede reemplazar o retirar un archivo sin nuestras marcas sin
	 * riesgo de tocar algo que no es nuestro.
	 *
	 * El archivo de cero bytes entra aquí a propósito: es lo que deja una
	 * escritura que falló en el primer byte y no tiene contenido que pueda ser
	 * de nadie.
	 *
	 * @param string $actual    Lo que hay en disco.
	 * @param string $plantilla Plantilla del paquete.
	 * @return bool
	 */
	private static function is_partial_copy( $actual, $plantilla ) {
		$actual    = (string) $actual;
		$plantilla = (string) $plantilla;
		$largo     = strlen( $actual );
		if ( $largo >= strlen( $plantilla ) ) {
			return false;
		}
		return 0 === strncmp( $plantilla, $actual, $largo );
	}

	/**
	 * Instala o actualiza el testigo.
	 *
	 * @return array
	 */
	public static function install() {
		$plantilla = self::template();
		if ( false === $plantilla ) {
			return array( 'ok' => false, 'message' => __( 'I did not find the watchdog template inside the plugin. Reinstall AI Bug Hunter.', 'ai-bug-hunter' ) );
		}

		$estado = self::status();
		// Nunca se pisa un archivo ajeno que se llame igual. Un testigo nuestro
		// a medio escribir NO es un archivo ajeno: status() lo marca como
		// 'partial' y sí se puede reemplazar, que es lo único que devuelve el
		// sitio sin bajar por FTP.
		if ( ! empty( $estado['foreign'] ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: ruta relativa. */
					__( 'There is already a file at %s that does not belong to AI Bug Hunter. I am not going to overwrite it: check it yourself and move it if appropriate.', 'ai-bug-hunter' ),
					$estado['path']
				),
			);
		}

		$dir = self::dir();
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'I could not create the mu-plugins folder.', 'ai-bug-hunter' ) ) );
		}
		if ( is_link( $dir ) || ! is_writable( $dir ) ) {
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'The mu-plugins folder does not allow writing from WordPress.', 'ai-bug-hunter' ) ) );
		}

		// Escritura atómica: nadie debe poder cargar un testigo a medio escribir.
		$destino = self::path();
		$tmp     = $destino . '.tmp-' . wp_generate_password( 8, false, false );
		$fh      = @fopen( $tmp, 'x+b' );
		if ( false === $fh ) {
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'I could not create the temporary file.', 'ai-bug-hunter' ) ) );
		}

		// Escritura por bucle con recuento de bytes. Un solo fwrite() —y también
		// file_put_contents(), que es lo que había aquí— puede escribir MENOS
		// bytes de los pedidos cuando el disco se llena, salta la cuota o el
		// filesystem es de red, y en ese caso devuelve un número, no false. Dar
		// por buena «cualquier cosa distinta de false» y renombrar encima
		// publicaba un testigo truncado, y este archivo se ejecuta antes que
		// WordPress en TODAS las peticiones: truncado no deja un vigilante
		// ciego, deja el sitio entero caído —portada y escritorio— sin salida
		// desde el navegador. Es la misma escritura que ABH_Core::write_core_file().
		$bytes = (string) $plantilla;
		$total = strlen( $bytes );
		$desde = 0;
		$ok    = true;
		while ( $desde < $total ) {
			$n = @fwrite( $fh, substr( $bytes, $desde, min( 1048576, $total - $desde ) ) );
			if ( false === $n || 0 === $n ) {
				$ok = false;
				break;
			}
			$desde += $n;
		}
		@fflush( $fh );
		if ( function_exists( 'fsync' ) ) {
			@fsync( $fh );
		}
		@fclose( $fh );

		if ( ! $ok || $desde !== $total ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'The write was left halfway through, most likely because the disk is full or a quota is in the way. I discarded the incomplete file: nothing was left in mu-plugins and the watchdog was not installed.', 'ai-bug-hunter' ) ) );
		}

		// La huella se comprueba ANTES de publicar nada. Un temporal que no es
		// byte a byte la plantilla no llega a renombrarse: aquí no ha pasado nada.
		$huella = hash( 'sha256', $bytes );
		if ( ! hash_equals( $huella, (string) @hash_file( 'sha256', $tmp ) ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'What reached the disk does not match the watchdog template, so I discarded it before putting it in place. Nothing was installed. Check the free space on the server and try again.', 'ai-bug-hunter' ) ) );
		}

		@chmod( $tmp, 0644 );
		if ( ! @rename( $tmp, $destino ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => self::manual_hint( __( 'I could not put the file in place.', 'ai-bug-hunter' ) ) );
		}
		clearstatcache( true, $destino );

		// Y se vuelve a verificar lo que quedó en disco, no lo que creímos
		// escribir. Si no coincide, el archivo publicado se BORRA en el acto: sin
		// testigo se pierde una función, con un testigo truncado no arranca ni
		// una petición del sitio. Lo que se borra es exactamente lo que acabamos
		// de poner nosotros dos líneas más arriba, nunca un archivo ajeno: los
		// ajenos ya se rechazaron antes de escribir.
		if ( ! hash_equals( $huella, (string) @hash_file( 'sha256', $destino ) ) ) {
			@unlink( $destino );
			clearstatcache( true, $destino );
			return array(
				'ok'      => false,
				'message' => __( 'The published file did not match the template, so I removed it to keep your site loading. The watchdog is not installed. Check the free disk space on the server and try again.', 'ai-bug-hunter' ),
			);
		}

		return array(
			'ok'      => true,
			'message' => __( 'Watchdog installed. From the next request on it will record any fatal error, including the ones that take the site down before WordPress manages to write the log. It only observes: it does not repair or modify anything.', 'ai-bug-hunter' ),
		);
	}

	/**
	 * Retira el testigo y borra lo que anotó.
	 *
	 * @return array
	 */
	public static function uninstall() {
		$estado = self::status();
		if ( empty( $estado['installed'] ) ) {
			delete_option( self::OPTION );
			return array( 'ok' => true, 'message' => __( 'There was no watchdog installed.', 'ai-bug-hunter' ) );
		}
		if ( ! empty( $estado['foreign'] ) ) {
			return array( 'ok' => false, 'message' => __( 'That file does not belong to AI Bug Hunter, so I will not touch it.', 'ai-bug-hunter' ) );
		}
		// Un testigo nuestro a medio escribir sí se retira desde aquí: es la
		// salida de emergencia cuando una escritura corta dejó en mu-plugins un
		// archivo que se ejecuta en cada petición y no compila.
		if ( ! @unlink( self::path() ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: ruta relativa. */
					__( 'I could not delete %s. Delete it over FTP or from your hosting file manager.', 'ai-bug-hunter' ),
					$estado['path']
				),
			);
		}
		delete_option( self::OPTION );
		if ( ! empty( $estado['partial'] ) ) {
			return array( 'ok' => true, 'message' => __( 'The watchdog file was incomplete, so I removed it and deleted its notes. Your site loads normally again. You can install the watchdog once there is free space on the server.', 'ai-bug-hunter' ) );
		}
		return array( 'ok' => true, 'message' => __( 'Watchdog removed and its notes deleted.', 'ai-bug-hunter' ) );
	}

	/**
	 * Lo que el testigo anotó, saneado al leerlo.
	 *
	 * Se revalida porque la opción vive en la base de datos y podría haberse
	 * alterado por fuera desde que se escribió.
	 *
	 * @return array
	 */
	public static function records() {
		$libro = get_option( self::OPTION, array() );
		if ( ! is_array( $libro ) ) {
			return array();
		}
		$out = array();
		foreach ( array_slice( $libro, 0, 20, true ) as $firma => $r ) {
			if ( ! is_array( $r ) || ! isset( $r['rel'], $r['line'], $r['last'] ) ) {
				continue;
			}
			$out[] = array(
				'sig'   => substr( preg_replace( '/[^a-f0-9]/', '', (string) $firma ), 0, 32 ),
				'kind'  => self::kind_label( isset( $r['kind'] ) ? (int) $r['kind'] : 0 ),
				'rel'   => substr( wp_strip_all_tags( (string) $r['rel'] ), 0, 200 ),
				'line'  => max( 0, (int) $r['line'] ),
				'msg'   => substr( wp_strip_all_tags( isset( $r['msg'] ) ? (string) $r['msg'] : '' ), 0, 300 ),
				'first' => (int) ( isset( $r['first'] ) ? $r['first'] : 0 ),
				'last'  => (int) $r['last'],
				'count' => max( 1, (int) ( isset( $r['count'] ) ? $r['count'] : 1 ) ),
			);
		}
		usort(
			$out,
			function ( $a, $b ) {
				return $b['last'] - $a['last'];
			}
		);
		return $out;
	}

	/**
	 * Borra las anotaciones sin retirar el testigo.
	 *
	 * @return array
	 */
	public static function clear() {
		delete_option( self::OPTION );
		return array( 'ok' => true, 'message' => __( 'Annotations cleared. The watchdog is still watching.', 'ai-bug-hunter' ) );
	}

	/**
	 * Nombre legible de un tipo de error de PHP.
	 *
	 * @param int $kind Constante de error.
	 * @return string
	 */
	private static function kind_label( $kind ) {
		$mapa = array(
			E_ERROR         => 'E_ERROR',
			E_PARSE         => 'E_PARSE',
			E_CORE_ERROR    => 'E_CORE_ERROR',
			E_COMPILE_ERROR => 'E_COMPILE_ERROR',
			E_USER_ERROR    => 'E_USER_ERROR',
		);
		return isset( $mapa[ $kind ] ) ? $mapa[ $kind ] : 'E_UNKNOWN';
	}

	/**
	 * Explica cómo instalarlo a mano cuando el servidor no deja escribir.
	 *
	 * @param string $motivo Qué falló.
	 * @return string
	 */
	private static function manual_hint( $motivo ) {
		return $motivo . ' ' . sprintf(
			/* translators: 1: archivo origen, 2: ruta destino. */
			__( 'You can install it by hand: copy %1$s from the plugin to %2$s on your site. It is a single loose file, not a folder.', 'ai-bug-hunter' ),
			'includes/watchdog-template.php',
			'wp-content/mu-plugins/' . self::FILENAME
		);
	}
}
