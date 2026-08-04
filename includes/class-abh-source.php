<?php
/**
 * Origen conocido de un archivo de wp-content.
 *
 * El núcleo de WordPress ya se compara contra su original (ABH_Core). Pero el
 * 99% de los archivos de un sitio no está en el núcleo, sino en plugins y temas
 * — y ahí también hay un original oficial contra el que comparar.
 *
 * Por qué importa: un archivo destrozado no se reconstruye razonando. Si el
 * daño borró información (un nombre de filtro, una llamada entera), no hay nada
 * en el archivo de donde deducirla; solo se puede recordar. Un modelo la
 * adivinaría, y adivinar dentro de una plantilla de pago es inaceptable.
 * Comparar contra el original es certeza; reconstruir es apuesta.
 *
 * Tres niveles de confianza, y el usuario ve cuál se aplicó:
 *
 *   manifiesto → WordPress.org publica el sha256 de ESE archivo. Certeza total.
 *   paquete    → viene del zip oficial por https, pero sin huella por archivo.
 *   ninguno    → sin fuente oficial. No hay nada que comparar; se aísla el daño.
 *
 * Esta clase compara y nada más. Lo único que llega a disco es el zip oficial
 * descargado por https, y vive en la caché del plugin, nunca en el sitio.
 * Ninguna función de este archivo escribe dentro de wp-content: quien devuelve
 * un archivo del núcleo a su original es ABH_Core, con su propia compuerta.
 * Hasta la tercera ronda hubo aquí un restore_file() sin llamador que escribía
 * los bytes del paquete en el sitio, y en el nivel «paquete» lo hacía sin huella
 * por archivo. Era la línea que más cerca quedaba de cruzar el límite de la
 * edición si alguien la cableaba; se eliminó por eso.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Lee cualquier archivo del sitio.
 *
 * POR QUE EXISTE:  Sin el código no hay diagnóstico. Leer es el suelo sobre el que se apoya todo lo demás.
 *
 * SI LO RECORTAS:  Lo que se lee es evidencia, no instrucciones. El contenido de un archivo del cliente jamás dirige el comportamiento del plugin.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Official-package caching verifies the archive contents, sets restrictive permissions, and promotes the download atomically on the same volume. Nothing here is written into the site.

/**
 * Class ABH_Source
 */
class ABH_Source {

	/**
	 * Identifica a qué plugin o tema pertenece una ruta, y en qué versión.
	 *
	 * @param string $rel Ruta relativa a ABSPATH.
	 * @return array kind, slug, version, inner, verifiable, reason.
	 */
	public static function identify( $rel ) {
		$rel  = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$nada = array( 'kind' => 'unknown', 'slug' => '', 'version' => '', 'inner' => '', 'verifiable' => false, 'reason' => '' );

		if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
			return $nada;
		}
		if ( 0 !== strpos( $rel, 'wp-content/plugins/' ) && 0 !== strpos( $rel, 'wp-content/themes/' ) ) {
			$nada['reason'] = __( 'The path does not belong to a plugin or a theme.', 'ai-bug-hunter' );
			return $nada;
		}

		$es_plugin = 0 === strpos( $rel, 'wp-content/plugins/' );
		$resto     = substr( $rel, $es_plugin ? 19 : 18 );
		$partes    = explode( '/', $resto, 2 );
		$slug      = isset( $partes[0] ) ? $partes[0] : '';
		$inner     = isset( $partes[1] ) ? $partes[1] : '';

		if ( '' === $slug || '' === $inner || ! preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $slug ) ) {
			$nada['reason'] = __( 'I could not identify the plugin or theme the file belongs to.', 'ai-bug-hunter' );
			return $nada;
		}

		$version = $es_plugin ? self::plugin_version( $slug ) : self::theme_version( $slug );
		if ( '' === $version ) {
			return array(
				'kind'       => $es_plugin ? 'plugin' : 'theme',
				'slug'       => $slug,
				'version'    => '',
				'inner'      => $inner,
				'verifiable' => false,
				'reason'     => __( 'I could not read the installed version, so I do not know which original to compare it against.', 'ai-bug-hunter' ),
			);
		}

		return array(
			'kind'       => $es_plugin ? 'plugin' : 'theme',
			'slug'       => $slug,
			'version'    => $version,
			'inner'      => $inner,
			'verifiable' => true,
			'reason'     => '',
		);
	}

	/**
	 * Versión instalada de un plugin, leída de su cabecera.
	 *
	 * @param string $slug Carpeta del plugin.
	 * @return string
	 */
	private static function plugin_version( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			// Este plugin trabaja sobre instalaciones rotas: si falta el helper
			// del núcleo, se rinde en vez de lanzar un fatal encima.
			$helper = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( ! is_readable( $helper ) ) {
				return '';
			}
			require_once $helper;
			if ( ! function_exists( 'get_plugins' ) ) {
				return '';
			}
		}
		foreach ( get_plugins() as $archivo => $datos ) {
			if ( 0 === strpos( $archivo, $slug . '/' ) && ! empty( $datos['Version'] ) ) {
				return self::clean_version( $datos['Version'] );
			}
		}
		return '';
	}

	/**
	 * Versión instalada de un tema.
	 *
	 * @param string $slug Carpeta del tema.
	 * @return string
	 */
	private static function theme_version( $slug ) {
		if ( ! function_exists( 'wp_get_theme' ) ) {
			return '';
		}
		$tema = wp_get_theme( $slug );
		if ( ! $tema || ! $tema->exists() ) {
			return '';
		}
		return self::clean_version( (string) $tema->get( 'Version' ) );
	}

	/**
	 * Normaliza una versión, o devuelve vacío si no tiene forma de versión.
	 *
	 * @param mixed $v Valor.
	 * @return string
	 */
	private static function clean_version( $v ) {
		$v = trim( (string) $v );
		return preg_match( '/^[0-9]+(\.[0-9]+){0,3}$/', $v ) ? $v : '';
	}

	/**
	 * Manifiesto oficial de huellas de un plugin de WordPress.org.
	 *
	 * Solo existe para plugins del directorio oficial. Los temas y los plugins
	 * de pago no lo publican, y eso cambia el nivel de confianza posible.
	 *
	 * @param string $slug    Plugin.
	 * @param string $version Versión.
	 * @return array|false Mapa ruta interna => sha256.
	 */
	public static function checksums( $slug, $version ) {
		if ( ! preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $slug ) || '' === self::clean_version( $version ) ) {
			return false;
		}
		$clave    = 'abh_src_sums_' . md5( $slug . '|' . $version );
		$guardado = get_transient( $clave );
		if ( is_array( $guardado ) ) {
			return $guardado;
		}
		if ( 'vacio' === $guardado ) {
			return false;
		}

		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$res = wp_remote_get( $url, array( 'timeout' => 20, 'sslverify' => true ) );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			// Un plugin de pago no tiene manifiesto: es lo normal, no un fallo.
			set_transient( $clave, 'vacio', DAY_IN_SECONDS );
			return false;
		}
		$json = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $json ) || empty( $json['files'] ) || ! is_array( $json['files'] ) ) {
			set_transient( $clave, 'vacio', DAY_IN_SECONDS );
			return false;
		}

		$mapa = array();
		foreach ( $json['files'] as $ruta => $huellas ) {
			if ( is_array( $huellas ) && ! empty( $huellas['sha256'] ) && is_string( $huellas['sha256'] ) ) {
				$mapa[ (string) $ruta ] = (string) $huellas['sha256'];
			}
		}
		if ( empty( $mapa ) ) {
			set_transient( $clave, 'vacio', DAY_IN_SECONDS );
			return false;
		}
		set_transient( $clave, $mapa, WEEK_IN_SECONDS );
		return $mapa;
	}

	/**
	 * Paquete oficial guardado en el repertorio, descargándolo si hace falta.
	 *
	 * @param string $kind    plugin o theme.
	 * @param string $slug    Carpeta.
	 * @param string $version Versión.
	 * @return string|false Ruta del zip.
	 */
	public static function ensure_package( $kind, $slug, $version ) {
		$dir = ABH_Core::cache_dir();
		if ( ! $dir ) {
			return false;
		}
		if ( ! in_array( $kind, array( 'plugin', 'theme' ), true ) ) {
			return false;
		}
		if ( ! preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $slug ) || '' === self::clean_version( $version ) ) {
			return false;
		}

		$destino = $dir . '/' . $kind . '-' . $slug . '-' . $version . '.zip';
		if ( is_file( $destino ) && filesize( $destino ) > 1024 ) {
			return $destino;
		}
		$freno = 'abh_src_fail_' . md5( $kind . '|' . $slug . '|' . $version );
		if ( get_transient( $freno ) ) {
			return false;
		}

		if ( ! function_exists( 'download_url' ) ) {
			$helper = ABSPATH . 'wp-admin/includes/file.php';
			if ( ! is_readable( $helper ) ) {
				return false;
			}
			require_once $helper;
			if ( ! function_exists( 'download_url' ) ) {
				return false;
			}
		}

		$url = 'https://downloads.wordpress.org/' . $kind . '/' . rawurlencode( $slug ) . '.' . rawurlencode( $version ) . '.zip';
		$tmp = download_url( $url, 180 );
		if ( is_wp_error( $tmp ) ) {
			set_transient( $freno, 1, 10 * MINUTE_IN_SECONDS );
			return false;
		}
		if ( filesize( $tmp ) < 1024 || ! self::looks_like_package( $tmp, $slug ) ) {
			@unlink( $tmp );
			set_transient( $freno, 1, 10 * MINUTE_IN_SECONDS );
			return false;
		}
		if ( ! @rename( $tmp, $destino ) ) {
			@unlink( $tmp );
			return false;
		}
		@chmod( $destino, 0600 );
		return $destino;
	}

	/**
	 * Comprueba que el zip contenga de verdad la carpeta esperada.
	 *
	 * @param string $zip  Ruta.
	 * @param string $slug Carpeta esperada.
	 * @return bool
	 */
	private static function looks_like_package( $zip, $slug ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return false;
		}
		$za = new ZipArchive();
		if ( true !== $za->open( $zip ) ) {
			return false;
		}
		$ok = false;
		for ( $i = 0; $i < min( 40, $za->numFiles ); $i++ ) {
			if ( 0 === strpos( (string) $za->getNameIndex( $i ), $slug . '/' ) ) {
				$ok = true;
				break;
			}
		}
		$za->close();
		return $ok;
	}

	/**
	 * Contenido oficial de un archivo, con el nivel de confianza alcanzado.
	 *
	 * @param string $rel Ruta relativa a ABSPATH.
	 * @return array|false content, confianza, origen.
	 */
	public static function official_file( $rel ) {
		$id = self::identify( $rel );
		if ( empty( $id['verifiable'] ) ) {
			return false;
		}
		$zip = self::ensure_package( $id['kind'], $id['slug'], $id['version'] );
		if ( ! $zip || ! class_exists( 'ZipArchive' ) ) {
			return false;
		}
		$za = new ZipArchive();
		if ( true !== $za->open( $zip ) ) {
			return false;
		}
		$cuerpo = $za->getFromName( $id['slug'] . '/' . $id['inner'] );
		$za->close();
		if ( false === $cuerpo ) {
			return false;
		}

		// Nivel 1: hay huella publicada para ESE archivo. Certeza total.
		$sumas = 'plugin' === $id['kind'] ? self::checksums( $id['slug'], $id['version'] ) : false;
		if ( is_array( $sumas ) && isset( $sumas[ $id['inner'] ] ) ) {
			if ( ! hash_equals( strtolower( $sumas[ $id['inner'] ] ), hash( 'sha256', $cuerpo ) ) ) {
				// El paquete no cuadra con su propio manifiesto: no se usa.
				return false;
			}
			return array( 'content' => $cuerpo, 'confianza' => 'manifiesto', 'origen' => $id );
		}

		// Nivel 2: viene del paquete oficial por https, sin huella por archivo.
		return array( 'content' => $cuerpo, 'confianza' => 'paquete', 'origen' => $id );
	}

	/**
	 * Estado de un archivo frente a su original oficial.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	public static function status( $rel ) {
		$id  = self::identify( $rel );
		$out = array(
			'known'     => ! empty( $id['verifiable'] ),
			'kind'      => $id['kind'],
			'slug'      => $id['slug'],
			'version'   => $id['version'],
			'altered'   => false,
			'confianza' => '',
			'reason'    => $id['reason'],
		);
		if ( empty( $id['verifiable'] ) ) {
			return $out;
		}
		$oficial = self::official_file( $rel );
		if ( false === $oficial ) {
			$out['known']  = false;
			$out['reason'] = sprintf(
				/* translators: 1: slug, 2: versión. */
				__( 'I could not get an official copy of %1$s %2$s to compare against.', 'ai-bug-hunter' ),
				$id['slug'],
				$id['version']
			);
			return $out;
		}
		$actual           = ABH_Engine::read_file( $rel );
		$out['confianza'] = $oficial['confianza'];
		$out['altered']   = ( false === $actual ) ? true : ( $actual !== $oficial['content'] );
		return $out;
	}

	/**
	 * Diferencia entre el archivo instalado y el oficial.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	public static function diff_file( $rel ) {
		$check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $check['allowed'] ) ) {
			return array( 'ok' => false, 'message' => __( 'That path is outside the area HUNTER AI can touch.', 'ai-bug-hunter' ) );
		}
		$oficial = self::official_file( $rel );
		if ( false === $oficial ) {
			$id = self::identify( $rel );
			return array(
				'ok'      => false,
				'message' => '' !== $id['reason']
					? $id['reason']
					: __( 'There is no official copy of this file to compare against. That is normal with paid plugins and with your own code.', 'ai-bug-hunter' ),
			);
		}
		$actual = ABH_Engine::read_file( $rel );
		$actual = ( false === $actual ) ? '' : $actual;
		if ( $actual === $oficial['content'] ) {
			return array(
				'ok'        => true,
				'identical' => true,
				'rel_path'  => $rel,
				'confianza' => $oficial['confianza'],
				'diff'      => array(),
				'message'   => sprintf(
					/* translators: %s: ruta. */
					__( '%s matches the original from its plugin or theme. This file is not damaged.', 'ai-bug-hunter' ),
					$rel
				),
			);
		}
		return array(
			'ok'        => true,
			'identical' => false,
			'rel_path'  => $rel,
			'confianza' => $oficial['confianza'],
			'origen'    => $oficial['origen'],
			'diff'      => ABH_Engine::diff_rows( $oficial['content'], $actual ),
			'message'   => sprintf(
				/* translators: 1: ruta, 2: slug, 3: versión. */
				__( 'Difference between %1$s and the original from %2$s %3$s. What is green is what is extra in your copy.', 'ai-bug-hunter' ),
				$rel,
				$oficial['origen']['slug'],
				$oficial['origen']['version']
			),
		);
	}

}
