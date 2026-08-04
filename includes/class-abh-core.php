<?php
/**
 * Integridad y riesgo del núcleo de WordPress.
 *
 * Todo lo de esta clase es determinista y no consume tokens: se apoya en las
 * APIs oficiales de WordPress.org (checksums MD5 por archivo). Ninguna
 * decisión depende de un modelo.
 *
 * Reglas que respeta:
 *  - Nunca escribe nada. Solo observa e informa.
 *  - No mantiene una lista propia de versiones vulnerables de WordPress. Los
 *    avisos de versión sólo pueden venir de una fuente que configure el
 *    administrador, y salen a pantalla como informativos y citando su origen.
 *  - Nunca propone volver a una versión con vulnerabilidad conocida: para una
 *    rama afectada, el destino correcto es siempre su versión parcheada.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Compara y restaura archivos del NÚCLEO de WordPress.
 *
 * POR QUE EXISTE:  Un núcleo modificado es un sitio comprometido o un sitio roto. Poder devolverlo a su estado original es reparar de verdad.
 *
 * SI LO RECORTAS:  Tocar el núcleo está permitido a propósito. Lo que no se toca es wp-config.php.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Verified core restoration needs atomic local replacement and byte-for-byte post-write verification unavailable through WP_Filesystem transports.

/**
 * Class ABH_Core
 */
class ABH_Core {

	/**
	 * Archivos comprobados por lote, para no agotar el tiempo de ejecución.
	 */
	const BATCH = 150;

	/**
	 * Prefijo del estado del escaneo.
	 */
	const STATE = 'abh_core_scan';

	/**
	 * Último escaneo completado. Sobrevive al transient a propósito.
	 */
	const LAST_SCAN = 'abh_core_last_scan';

	/**
	 * Versión instalada de WordPress.
	 *
	 * @return string
	 */
	public static function installed_version() {
		global $wp_version;
		if ( isset( $wp_version ) && '' !== (string) $wp_version ) {
			return (string) $wp_version;
		}
		$file = ABSPATH . 'wp-includes/version.php';
		if ( is_readable( $file ) ) {
			$contenido = (string) @file_get_contents( $file );
			if ( preg_match( '/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $contenido, $m ) ) {
				return $m[1];
			}
		}
		return '';
	}

	/**
	 * Avisos de versión del núcleo, según las fuentes que haya configurado el
	 * administrador del sitio.
	 *
	 * La lista por defecto está VACÍA, y está vacía a propósito.
	 *
	 * Este plugin no tiene autoridad para afirmar que una versión concreta de
	 * WordPress tenga una vulnerabilidad, y menos aún que se esté explotando.
	 * Eso lo publica el equipo de seguridad de WordPress con su nombre detrás.
	 * Una tabla escrita a mano aquí decía justamente eso —«crítica», «abuso
	 * activo»— sobre releases vigentes, sin citar ninguna fuente y sin forma de
	 * envejecer: cada versión que salía la dejaba más falsa, y quien la leía en
	 * su panel la leía con la autoridad prestada del escritorio de WordPress.
	 * Alarmar así a un administrador es desinformarle, no protegerle.
	 *
	 * El MECANISMO se conserva entero, porque el mecanismo sí es legítimo: quien
	 * quiera avisos configura un feed (ABH_CVE, con ABH_CVE_FEED_URL) o engancha
	 * este filtro. Lo que llegue por ahí es contenido observado de un tercero:
	 * se valida entrada por entrada, se muestra como informativo y citando su
	 * origen, y nunca como veredicto de este plugin.
	 *
	 * Cada entrada declara el intervalo afectado [desde, hasta) y la versión
	 * parcheada de ESA rama.
	 *
	 * @return array
	 */
	public static function known_vulnerabilities() {
		$tabla = apply_filters( 'abh_core_known_vulnerabilities', array() );
		// Un filtro es código de otro: si devuelve cualquier cosa, aquí no se
		// recorre nada. Antes la tabla propia garantizaba el tipo; ya no.
		return is_array( $tabla ) ? $tabla : array();
	}

	/**
	 * Comprueba si alguna fuente configurada menciona la versión instalada.
	 *
	 * Sin fuentes configuradas no hay avisos, y no haberlos no significa que la
	 * versión sea segura: significa que aquí nadie tiene nada que decir. El
	 * texto que sale a pantalla lo dice con esas palabras, porque un «no
	 * aparece en la lista» sobre una lista vacía se lee como un certificado.
	 *
	 * @param string $version Versión a evaluar. Vacío = la instalada.
	 * @return array
	 */
	public static function version_risk( $version = '' ) {
		$version = '' !== $version ? $version : self::installed_version();
		if ( '' === $version ) {
			return array(
				'ok'      => false,
				'version' => '',
				'message' => __( 'I could not determine the installed WordPress version.', 'ai-bug-hunter' ),
			);
		}

		$hallazgos = array();
		foreach ( self::known_vulnerabilities() as $vuln ) {
			// Todo esto entra por un filtro, así que se comprueba la forma antes
			// de tocarlo: una entrada mal armada se ignora, no rompe la página.
			if ( ! is_array( $vuln ) || empty( $vuln['rangos'] ) || ! is_array( $vuln['rangos'] ) ) {
				continue;
			}
			foreach ( $vuln['rangos'] as $rango ) {
				if ( ! is_array( $rango ) || ! isset( $rango['desde'], $rango['hasta'], $rango['parche'] ) ) {
					continue;
				}
				if ( version_compare( $version, $rango['desde'], '>=' ) && version_compare( $version, $rango['hasta'], '<' ) ) {
					$hallazgos[] = array(
						'id'        => isset( $vuln['id'] ) ? (string) $vuln['id'] : '',
						'alias'     => isset( $vuln['alias'] ) ? (string) $vuln['alias'] : '',
						'severidad' => isset( $vuln['severidad'] ) ? (string) $vuln['severidad'] : '',
						'resumen'   => isset( $vuln['resumen'] ) ? (string) $vuln['resumen'] : '',
						'parche'    => (string) $rango['parche'],
					);
					break;
				}
			}
		}

		if ( empty( $hallazgos ) ) {
			$mensaje = sprintf(
				/* translators: %s: versión instalada. */
				__( 'No security advisory source configured on this site mentions WordPress %s. This plugin does not keep its own list of affected WordPress versions, so this is not a clean bill of health: check WordPress.org for the current release.', 'ai-bug-hunter' ),
				$version
			);
		} else {
			$aviso   = $hallazgos[0];
			$mensaje = sprintf(
				/* translators: 1: versión instalada, 2: identificador del aviso, 3: versión que el aviso da como corregida. */
				__( 'Informational: an advisory source configured on this site (%2$s) places WordPress %1$s inside an affected range and gives %3$s as the fixed release for that branch. This is reported information, not a finding of this plugin, and it says nothing about whether this site was attacked. Confirm it with the source and with WordPress.org before acting.', 'ai-bug-hunter' ),
				$version,
				'' !== $aviso['id'] ? $aviso['id'] : __( 'no identifier given', 'ai-bug-hunter' ),
				$aviso['parche']
			);
			// El resumen del feed ya llega con su atribución delante (ABH_CVE lo
			// compone al leer). Se añade tal cual: es lo que hace que el aviso
			// nunca aparezca en pantalla sin decir quién lo publica.
			if ( '' !== $aviso['resumen'] ) {
				$mensaje .= ' ' . $aviso['resumen'];
			}
		}

		return array(
			'ok'         => true,
			'version'    => $version,
			// «Hay un aviso de una fuente configurada», no «este plugin declara
			// vulnerable tu WordPress». La clave conserva el nombre porque
			// class-abh-admin.php se apoya en ella.
			'vulnerable' => ! empty( $hallazgos ),
			'hallazgos'  => $hallazgos,
			// El destino seguro es SIEMPRE la versión parcheada de la propia
			// rama. Nunca una versión anterior, por muy "estable" que parezca.
			'destino'    => ! empty( $hallazgos ) ? $hallazgos[0]['parche'] : '',
			'message'    => $mensaje,
		);
	}

	/**
	 * Descarga (y cachea) los checksums oficiales del núcleo.
	 *
	 * @param string $version Versión.
	 * @param string $locale  Idioma de la instalación.
	 * @return array|false Mapa ruta relativa => md5.
	 */
	public static function checksums( $version = '', $locale = '' ) {
		$version = '' !== $version ? $version : self::installed_version();
		$locale  = '' !== $locale ? $locale : get_locale();
		if ( '' === $version ) {
			return false;
		}

		$clave    = 'abh_core_sums_' . md5( $version . '|' . $locale );
		$guardado = get_transient( $clave );
		if ( is_array( $guardado ) ) {
			return $guardado;
		}

		$url = add_query_arg(
			array(
				'version' => rawurlencode( $version ),
				'locale'  => rawurlencode( $locale ),
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);
		$res = wp_remote_get( $url, array( 'timeout' => 20, 'sslverify' => true ) );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return false;
		}
		$json = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $json ) || empty( $json['checksums'] ) || ! is_array( $json['checksums'] ) ) {
			return false;
		}

		set_transient( $clave, $json['checksums'], WEEK_IN_SECONDS );
		return $json['checksums'];
	}

	/**
	 * Prepara un escaneo de integridad del núcleo.
	 *
	 * @return array
	 */
	public static function scan_start() {
		$version = self::installed_version();
		$locale  = get_locale();
		$sumas   = self::checksums( $version, $locale );
		if ( false === $sumas ) {
			return array(
				'ok'      => false,
				'message' => __( 'I could not obtain the official fingerprints from WordPress.org. Check that the server allows outgoing connections and try again.', 'ai-bug-hunter' ),
			);
		}

		$estado = array(
			'version'  => $version,
			'locale'   => $locale,
			'files'    => array_keys( $sumas ),
			'index'    => 0,
			'modified' => array(),
			'missing'  => array(),
			'accepted' => array(),
			'user'     => get_current_user_id(),
			'started'  => time(),
		);
		set_transient( self::STATE . '_' . get_current_user_id(), $estado, HOUR_IN_SECONDS );

		return array(
			'ok'      => true,
			'version' => $version,
			'total'   => count( $estado['files'] ),
			'risk'    => self::version_risk( $version ),
		);
	}

	/**
	 * Comprueba un lote de archivos del núcleo.
	 *
	 * @return array
	 */
	public static function scan_step() {
		$clave  = self::STATE . '_' . get_current_user_id();
		$estado = get_transient( $clave );
		if ( ! is_array( $estado ) || ! isset( $estado['files'] ) ) {
			return array( 'ok' => false, 'message' => __( 'The core scan expired. Start it again.', 'ai-bug-hunter' ) );
		}
		$sumas = self::checksums( $estado['version'], $estado['locale'] );
		if ( false === $sumas ) {
			return array( 'ok' => false, 'message' => __( 'The official fingerprints were lost. Start the scan again.', 'ai-bug-hunter' ) );
		}

		$aceptados = self::accepted();
		$total     = count( $estado['files'] );
		$hasta     = min( $total, $estado['index'] + self::BATCH );
		for ( $i = $estado['index']; $i < $hasta; $i++ ) {
			$rel = $estado['files'][ $i ];
			// wp-content nunca forma parte de la identidad del núcleo: ahí vive
			// lo del usuario y comparar su hash daría falsos positivos.
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				continue;
			}
			if ( ! isset( $sumas[ $rel ] ) ) {
				continue;
			}
			$abs = ABSPATH . $rel;
			if ( ! file_exists( $abs ) ) {
				$estado['missing'][] = $rel;
				continue;
			}
			$md5 = @md5_file( $abs );
			if ( false === $md5 ) {
				continue;
			}
			if ( ! hash_equals( (string) $sumas[ $rel ], (string) $md5 ) ) {
				// Una modificación declarada intencional deja de ser hallazgo,
				// pero solo mientras el archivo siga exactamente como se aceptó.
				if ( isset( $aceptados[ $rel ] ) && hash_equals( (string) $aceptados[ $rel ], (string) $md5 ) ) {
					$estado['accepted'][] = $rel;
					continue;
				}
				$estado['modified'][] = $rel;
			}
		}
		$estado['index'] = $hasta;
		set_transient( $clave, $estado, HOUR_IN_SECONDS );

		$terminado = $hasta >= $total;
		$salida    = array(
			'ok'       => true,
			'done'     => $terminado,
			'checked'  => $hasta,
			'total'    => $total,
			'modified' => count( $estado['modified'] ),
			'missing'  => count( $estado['missing'] ),
			'accepted' => count( $estado['accepted'] ),
		);
		if ( $terminado ) {
			$salida['files_modified'] = array_slice( $estado['modified'], 0, 100 );
			$salida['files_missing']  = array_slice( $estado['missing'], 0, 100 );
			$salida['files_accepted'] = array_slice( $estado['accepted'], 0, 100 );
			$salida['risk']           = self::version_risk( $estado['version'] );
			$salida['message']        = self::verdict( $estado );

			// El resultado sobrevive al transient: hace falta después para
			// poder decir de dónde viene un «Call to undefined function».
			update_option(
				self::LAST_SCAN,
				array(
					'version'  => $estado['version'],
					'locale'   => $estado['locale'],
					'when'     => time(),
					'modified' => array_values( $estado['modified'] ),
					'missing'  => array_values( $estado['missing'] ),
					'accepted' => array_values( $estado['accepted'] ),
				),
				false
			);
			delete_transient( $clave );
		}
		return $salida;
	}

	/**
	 * Modificaciones que el administrador declaró intencionales.
	 *
	 * Se guarda la huella aceptada, no solo la ruta: si el archivo vuelve a
	 * cambiar, deja de estar aceptado y se avisa de nuevo. Así una excepción
	 * legítima no se convierte en un punto ciego permanente.
	 *
	 * @return array ruta => md5 aceptado.
	 */
	public static function accepted() {
		$a = get_option( 'abh_core_accepted', array() );
		return is_array( $a ) ? $a : array();
	}

	/**
	 * Declara intencional la modificación actual de un archivo del núcleo.
	 *
	 * @param string $rel Ruta relativa a ABSPATH.
	 * @return array
	 */
	public static function accept( $rel ) {
		$abs = self::core_path( $rel );
		if ( ! $abs || ! file_exists( $abs ) ) {
			return array( 'ok' => false, 'message' => __( 'That core file does not exist or is out of scope.', 'ai-bug-hunter' ) );
		}
		$a           = self::accepted();
		$a[ $rel ]   = (string) @md5_file( $abs );
		update_option( 'abh_core_accepted', $a, false );
		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: %s: ruta. */
				__( 'Marked as an intentional change: %s. If the file changes again, I will let you know.', 'ai-bug-hunter' ),
				$rel
			),
		);
	}

	/**
	 * Resuelve y valida una ruta del núcleo.
	 *
	 * Lista blanca estricta: la ruta debe existir en el manifiesto oficial de
	 * la versión instalada, quedar dentro de ABSPATH y no ser wp-config.php ni
	 * nada bajo wp-content/. No se reutiliza el alcance de escritura del motor
	 * (limitado a wp-content) porque aquí el permiso lo concede el propio
	 * manifiesto de WordPress, no una raíz configurable.
	 *
	 * @param string $rel Ruta relativa.
	 * @return string|false Ruta absoluta validada.
	 */
	public static function core_path( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		if ( '' === $rel || false !== strpos( $rel, '..' ) ) {
			return false;
		}
		if ( 'wp-config.php' === $rel || 0 === strpos( $rel, 'wp-content/' ) ) {
			return false;
		}
		// La lista de intocables vive en ABH_Limits, y ABH_Limits nombra a ESTA
		// función como quien la hace cumplir para la restauración de originales.
		// No la consultaba: wp-settings.php y wp-load.php están declarados
		// intocables y sí figuran en los checksums oficiales, así que la ruta
		// los aceptaba. El aviso al cliente prometía una frontera que el código
		// no aplicaba — el mismo defecto de siempre, una copia sin actualizar.
		// Aquí NO se consulta ABH_Limits::is_never(), y la diferencia es de
		// fondo, no un descuido.
		//
		// Esa lista contesta una pregunta concreta: ¿puede escribirse en este
		// archivo contenido REDACTADO POR ALGUIEN —un modelo, un plan, una
		// propuesta? Para .htaccess, .user.ini, php.ini o web.config la
		// respuesta es que no, jamás, porque ahí se decide cómo el servidor
		// ejecuta el sitio.
		//
		// Esta función contesta otra: ¿puede devolverse este archivo a los
		// bytes OFICIALES de WordPress, comprobados contra el checksum de
		// wordpress.org? Ahí no hay autoría de nadie; el contenido es el mismo
		// que trae una instalación limpia.
		//
		// Consultar la lista aquí rompía justo el caso que más importa:
		// wp-settings.php, wp-load.php y wp-blog-header.php son del núcleo, sí
		// figuran en los checksums, y son de los primeros que toca el malware.
		// Bloquear su restauración dejaba tres botones muertos en el panel de
		// integridad y una restauración ya hecha sin forma de revertirse.
		//
		// El resto de la lista no necesita bloqueo aquí: .htaccess, .user.ini,
		// php.ini y web.config no son del núcleo y no aparecen en ningún
		// checksum, así que la comprobación de abajo ya los rechaza sola.
		// wp-config.php se rechaza arriba, en su propia línea.
		$sumas = self::checksums();
		if ( ! is_array( $sumas ) || ! isset( $sumas[ $rel ] ) ) {
			return false;
		}
		$raiz = rtrim( wp_normalize_path( ABSPATH ), '/' );
		$abs  = wp_normalize_path( $raiz . '/' . $rel );
		if ( 0 !== strpos( $abs, $raiz . '/' ) ) {
			return false;
		}
		return $abs;
	}

	/**
	 * Descarga el archivo oficial de esa versión y verifica su huella.
	 *
	 * Fuente: el repositorio de etiquetas del núcleo, que entrega archivos
	 * sueltos (no hace falta bajar WordPress entero). El contenido solo se
	 * acepta si su MD5 coincide con el checksum oficial: si no coincide, no
	 * se devuelve nada y por tanto nunca se escribe.
	 *
	 * @param string $rel     Ruta relativa.
	 * @param string $version Versión.
	 * @return string|false
	 */
	public static function official_file( $rel, $version = '' ) {
		$version = '' !== $version ? $version : self::installed_version();
		$locale  = get_locale();
		$sumas   = self::checksums( $version, $locale );
		if ( ! is_array( $sumas ) || ! isset( $sumas[ $rel ] ) ) {
			return false;
		}

		// Vía barata: un solo archivo del repositorio de etiquetas. Vale para
		// la inmensa mayoría, que es idéntica en todos los idiomas.
		$url = 'https://core.svn.wordpress.org/tags/' . rawurlencode( $version ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) );
		$res = wp_remote_get( $url, array( 'timeout' => 25, 'sslverify' => true ) );
		if ( ! is_wp_error( $res ) && 200 === (int) wp_remote_retrieve_response_code( $res ) ) {
			$cuerpo = (string) wp_remote_retrieve_body( $res );
			// La huella manda: sin coincidencia exacta, el archivo se descarta.
			if ( hash_equals( (string) $sumas[ $rel ], md5( $cuerpo ) ) ) {
				return $cuerpo;
			}
		}

		// Ese repositorio publica la compilación en inglés y los paquetes
		// traducidos no son idénticos: wp-includes/version.php, por ejemplo,
		// lleva $wp_local_package. Para esos archivos hay que ir al paquete
		// oficial del idioma, que queda guardado en el repertorio del servidor
		// y solo se descarga una vez. La huella sigue mandando.
		return self::package_file( $rel, $version, $locale );
	}

	/**
	 * Compara el archivo instalado con el oficial.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	public static function diff_file( $rel ) {
		$abs = self::core_path( $rel );
		if ( ! $abs ) {
			return array( 'ok' => false, 'message' => __( 'That path is not part of the core of this WordPress version.', 'ai-bug-hunter' ) );
		}
		$oficial = self::official_file( $rel );
		if ( false === $oficial ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: versión, 2: idioma. */
					__( 'I could not get a verified official copy of %1$s in %2$s. Nothing was touched. If your server cannot download from WordPress.org, this check cannot be completed.', 'ai-bug-hunter' ),
					self::installed_version(),
					get_locale()
				),
			);
		}
		$existe = file_exists( $abs );
		$actual = $existe ? (string) @file_get_contents( $abs ) : '';
		if ( $existe && $actual === $oficial ) {
			return array(
				'ok'        => true,
				'rel_path'  => $rel,
				'faltante'  => false,
				'identical' => true,
				'diff'      => array(),
				'message'   => sprintf(
					/* translators: %s: ruta. */
					__( '%s matches the WordPress original byte for byte: this file is not damaged and there is nothing to restore. An error showing up here means the damage is in ANOTHER file, and that this one was only using it.', 'ai-bug-hunter' ),
					$rel
				),
			);
		}
		return array(
			'ok'        => true,
			'rel_path'  => $rel,
			'faltante'  => ! $existe,
			'identical' => false,
			'diff'      => ABH_Engine::diff_rows( $oficial, $actual ),
			'message'   => $existe
				? sprintf(
					/* translators: %s: ruta. */
					__( 'Difference between the official file and the one you have installed in %s. What was added (green) is what is extra in your copy.', 'ai-bug-hunter' ),
					$rel
				)
				: sprintf(
					/* translators: %s: ruta. */
					__( '%s does not exist in your installation. In green is the official content that would be written if you restore it.', 'ai-bug-hunter' ),
					$rel
				),
		);
	}

	/**
	 * Restaura un archivo del núcleo a su versión oficial.
	 *
	 * Crea respaldo cifrado antes de escribir y registra la operación en el
	 * historial con acción propia, para poder revertirla después.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	public static function restore_file( $rel ) {
		$abs = self::core_path( $rel );
		if ( ! $abs ) {
			return array( 'ok' => false, 'message' => __( 'That path is not part of the core of this WordPress version.', 'ai-bug-hunter' ) );
		}
		$oficial = self::official_file( $rel );
		if ( false === $oficial ) {
			return array( 'ok' => false, 'message' => __( 'I could not obtain and verify the official file. Nothing was written.', 'ai-bug-hunter' ) );
		}
		$actual = file_exists( $abs ) ? (string) @file_get_contents( $abs ) : '';
		if ( $actual === $oficial ) {
			return array(
				'ok'      => false,
				'message' => __( 'This file is already identical to the official one, so restoring it would change nothing. The error you see is caused by another file; use «Where is the cause?» to locate it.', 'ai-bug-hunter' ),
			);
		}

		$snap = false;
		if ( '' !== $actual ) {
			$snap = ABH_Backup::snapshot( $rel, $actual );
			if ( ! $snap ) {
				return array( 'ok' => false, 'message' => __( 'The backup could not be created, so nothing was restored.', 'ai-bug-hunter' ) );
			}
		}

		$escrito = self::write_core_file( $abs, $oficial );
		if ( empty( $escrito['ok'] ) ) {
			// «Revierte desde Historial de inmediato» sólo es un consejo honesto
			// si en Historial hay algo. Cuando la publicación se descubre
			// corrupta DESPUÉS del reemplazo, el asiento no llegaba a
			// escribirse —el retorno temprano se lo saltaba—, así que mandábamos
			// al operador a un botón que no existía. Se asienta aquí.
			if ( ! empty( $escrito['mismatch'] ) ) {
				if ( $snap ) {
					ABH_Backup::record(
						array(
							'op_id'       => $snap['op_id'],
							'action'      => 'core_restore',
							// NO es 'applied'. Un asiento aplicado hace que
							// last_applied_for() dé la incidencia por resuelta, y
							// esta operación falló: el archivo sigue mal y tiene
							// que seguir apareciendo como pendiente. El asiento
							// existe sólo para que el respaldo sea alcanzable.
							'status'      => 'failed',
							'rel_path'    => $rel,
							'sha_before'  => hash( 'sha256', $actual ),
							'sha_after'   => '',
							'backup_file' => $snap['file'],
							'model'       => ABH_Motor::SIGNATURE,
							'incident'    => __( 'Restore of a WordPress core file', 'ai-bug-hunter' ),
							'diagnosis'   => sprintf(
								/* translators: %s: ruta. */
								__( 'The restore of %s was published with the wrong fingerprint. The content you had before is saved here. Revert tries to bring it back; if that write also comes out corrupted, the problem is in the disk and the core has to be reinstalled.', 'ai-bug-hunter' ),
								$rel
							),
						)
					);
				} else {
					// No había contenido anterior: el archivo faltaba. No hay
					// nada que revertir, y decirlo es más útil que insinuarlo.
					$escrito['message'] = sprintf(
						/* translators: %s: ruta. */
						__( 'The write to %s was published with the wrong fingerprint, and that file did not exist before, so there is NO previous copy to revert to. Reinstall WordPress from Dashboard › Updates to leave the core consistent.', 'ai-bug-hunter' ),
						$rel
					);
				}
			}
			return $escrito;
		}

		ABH_Backup::record(
			array(
				'op_id'       => $snap ? $snap['op_id'] : substr( hash( 'sha256', $rel . microtime( true ) ), 0, 16 ),
				'action'      => 'core_restore',
				'rel_path'    => $rel,
				'sha_before'  => '' !== $actual ? hash( 'sha256', $actual ) : '',
				'sha_after'   => hash( 'sha256', $oficial ),
				'backup_file' => $snap ? $snap['file'] : '',
				'model'       => ABH_Motor::SIGNATURE,
				'incident'    => __( 'Restore of a WordPress core file', 'ai-bug-hunter' ),
				'diagnosis'   => sprintf(
					/* translators: 1: ruta, 2: versión. */
					__( '%1$s was restored to its official WordPress %2$s content, verified by MD5 fingerprint.', 'ai-bug-hunter' ),
					$rel,
					self::installed_version()
				),
			)
		);

		// Si estaba aceptado como intencional, deja de estarlo: ya no lo es.
		$a = self::accepted();
		if ( isset( $a[ $rel ] ) ) {
			unset( $a[ $rel ] );
			update_option( 'abh_core_accepted', $a, false );
		}

		// El aviso de respaldo sólo se da cuando hubo respaldo. Si el archivo no
		// existía, no se copió nada y el botón Revertir no tendría contenido que
		// devolver: prometerlo es peor que callarlo.
		$mensaje = $snap
			? sprintf(
				/* translators: %s: ruta. */
				__( 'Restored to its official version: %s. The previous content was backed up and you can revert it from History.', 'ai-bug-hunter' ),
				$rel
			)
			: sprintf(
				/* translators: %s: ruta. */
				__( 'Restored to its official version: %s. That file did not exist, so there is no previous content to revert.', 'ai-bug-hunter' ),
				$rel
			);

		return array(
			'ok'      => true,
			'message' => $mensaje,
		);
	}

	/**
	 * Escritura atómica de un archivo del núcleo ya validado.
	 *
	 * @param string $abs       Ruta absoluta validada por core_path().
	 * @param string $contenido Contenido oficial verificado.
	 * @return array
	 */
	public static function write_core_file( $abs, $contenido ) {
		$dir = dirname( $abs );
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return array( 'ok' => false, 'message' => __( 'The core directory does not allow writing on this server.', 'ai-bug-hunter' ) );
		}
		$modo = file_exists( $abs ) ? ( @fileperms( $abs ) & 0777 ) : 0644;
		$tmp  = $abs . '.abhtmp-' . wp_generate_password( 8, false, false );
		$fh   = @fopen( $tmp, 'x+b' );
		if ( false === $fh ) {
			return array( 'ok' => false, 'message' => __( 'I could not create the temporary file for the restore.', 'ai-bug-hunter' ) );
		}
		// Escritura por bucle. Un solo fwrite() puede escribir MENOS bytes de
		// los pedidos —cuota, disco lleno, filesystem de red— y devolver un
		// número, no false. Aceptar «cualquier cosa distinta de false» y
		// renombrar encima publicaba un archivo del núcleo truncado y dejaba el
		// sitio caído. El motor normal ya escribía así desde hace tiempo; esta
		// ruta se quedó con la versión ingenua.
		$bytes = (string) $contenido;
		$falta = strlen( $bytes );
		$desde = 0;
		$ok    = true;
		while ( $falta > 0 ) {
			$n = @fwrite( $fh, substr( $bytes, $desde, min( 1048576, $falta ) ) );
			if ( false === $n || 0 === $n ) {
				$ok = false;
				break;
			}
			$desde += $n;
			$falta -= $n;
		}
		@fflush( $fh );
		if ( function_exists( 'fsync' ) ) {
			@fsync( $fh );
		}
		@fclose( $fh );

		if ( ! $ok || $desde !== strlen( $bytes ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => __( 'The write was left incomplete and was discarded. The original file was not touched.', 'ai-bug-hunter' ) );
		}

		// El temporal tiene que ser byte a byte lo que se pidió escribir ANTES
		// de sustituir nada. Si no lo es, aquí no ha pasado nada.
		$huella_pedida = hash( 'sha256', $bytes );
		if ( ! hash_equals( $huella_pedida, (string) @hash_file( 'sha256', $tmp ) ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => __( 'What was written to disk does not match the downloaded original. It was discarded without touching the file.', 'ai-bug-hunter' ) );
		}

		@chmod( $tmp, $modo ? $modo : 0644 );
		if ( ! @rename( $tmp, $abs ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => __( 'I could not replace the original file.', 'ai-bug-hunter' ) );
		}
		clearstatcache( true, $abs );

		// Y comprobación DESPUÉS de publicar. Si lo que quedó en su sitio no es
		// lo que se verificó, el archivo del núcleo está mal y hay que decirlo
		// en voz alta: quien llama tiene el respaldo para revertir.
		if ( ! hash_equals( $huella_pedida, (string) @hash_file( 'sha256', $abs ) ) ) {
			return array(
				'ok'       => false,
				'mismatch' => true,
				'message'  => __( 'The published file does not match the verified original. Revert from History immediately and check the server\'s disk.', 'ai-bug-hunter' ),
			);
		}

		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $abs, true );
		}
		return array( 'ok' => true );
	}

	/**
	 * Redacta el veredicto del escaneo en lenguaje claro.
	 *
	 * @param array $estado Estado final.
	 * @return string
	 */
	private static function verdict( $estado ) {
		$mod  = count( $estado['modified'] );
		$fal  = count( $estado['missing'] );
		$risk = self::version_risk( $estado['version'] );

		$partes = array();
		if ( 0 === $mod && 0 === $fal ) {
			$partes[] = sprintf(
				/* translators: %s: versión. */
				__( 'The core files match the official WordPress %s files exactly.', 'ai-bug-hunter' ),
				$estado['version']
			);
		} else {
			$partes[] = sprintf(
				/* translators: 1: modificados, 2: faltantes. */
				__( 'I found %1$d altered core file(s) and %2$d missing one(s) compared to the official ones. A modified core file may be a manual edit or an unauthorized persistent change.', 'ai-bug-hunter' ),
				$mod,
				$fal
			);
		}
		if ( ! empty( $risk['vulnerable'] ) ) {
			$partes[] = $risk['message'];
		}
		return implode( ' ', $partes );
	}

	/**
	 * Carpeta del repertorio: paquetes oficiales ya descargados.
	 *
	 * Vive dentro del almacén privado del plugin, que ya está blindado (0700
	 * y .htaccess). Así una instalación solo descarga cada versión una vez.
	 *
	 * @return string|false
	 */
	public static function cache_dir() {
		if ( ! ABH_Backup::prepare_storage() ) {
			return false;
		}
		$dir = ABH_Backup::dir() . '/core-cache';
		if ( is_link( $dir ) ) {
			return false;
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return false;
		}
		@chmod( $dir, 0700 );
		return $dir;
	}

	/**
	 * Direcciones candidatas del paquete oficial de una versión e idioma.
	 *
	 * Se prueban en orden y la huella decide: una dirección equivocada no
	 * puede colar nada, porque el archivo extraído se compara igualmente
	 * contra el checksum oficial antes de usarse.
	 *
	 * @param string $version Versión.
	 * @param string $locale  Idioma, por ejemplo es_ES.
	 * @return array
	 */
	public static function package_urls( $version, $locale ) {
		$version = trim( (string) $version );
		$locale  = trim( (string) $locale );
		if ( '' === $version || ! preg_match( '/^[0-9][0-9.]{0,15}$/', $version ) ) {
			return array();
		}

		if ( '' === $locale || 'en_US' === $locale ) {
			return array(
				'https://downloads.wordpress.org/release/wordpress-' . $version . '.zip',
				'https://wordpress.org/wordpress-' . $version . '.zip',
			);
		}
		if ( ! preg_match( '/^[a-z]{2,3}(_[A-Za-z0-9]{2,8})?$/', $locale ) ) {
			return array();
		}

		$sub  = strtolower( substr( $locale, 0, strpos( $locale . '_', '_' ) ) );
		$urls = array(
			'https://' . $sub . '.wordpress.org/wordpress-' . $version . '-' . $locale . '.zip',
			'https://downloads.wordpress.org/release/' . $locale . '/wordpress-' . $version . '.zip',
		);
		// Último recurso: el paquete en inglés. Solo servirá para los archivos
		// que sean idénticos entre idiomas, porque el resto no pasará la huella.
		$urls[] = 'https://downloads.wordpress.org/release/wordpress-' . $version . '.zip';
		return $urls;
	}

	/**
	 * Qué paquetes ya están en el servidor.
	 *
	 * @return array
	 */
	public static function repertoire() {
		$dir = self::cache_dir();
		if ( ! $dir ) {
			return array();
		}
		$lista = array();
		foreach ( (array) glob( $dir . '/wordpress-*.zip' ) as $f ) {
			if ( ! is_file( $f ) ) {
				continue;
			}
			$nombre = basename( $f );
			if ( ! preg_match( '/^wordpress-([0-9][0-9.]*)-([A-Za-z0-9_]+)\.zip$/', $nombre, $m ) ) {
				continue;
			}
			$lista[] = array(
				'version' => $m[1],
				'locale'  => $m[2],
				'bytes'   => (int) filesize( $f ),
				'file'    => $nombre,
			);
		}
		return $lista;
	}

	/**
	 * Asegura que el paquete oficial esté descargado en el repertorio.
	 *
	 * @param string $version Versión.
	 * @param string $locale  Idioma.
	 * @return string|false Ruta del zip.
	 */
	public static function ensure_package( $version, $locale ) {
		$dir = self::cache_dir();
		if ( ! $dir ) {
			return false;
		}
		$version = trim( (string) $version );
		$locale  = '' !== $locale ? $locale : 'en_US';
		if ( ! preg_match( '/^[0-9][0-9.]{0,15}$/', $version ) || ! preg_match( '/^[A-Za-z0-9_]{2,12}$/', $locale ) ) {
			return false;
		}

		$destino = $dir . '/wordpress-' . $version . '-' . $locale . '.zip';
		if ( is_file( $destino ) && filesize( $destino ) > 1048576 ) {
			return $destino;
		}

		// Una descarga fallida no se reintenta en bucle en cada clic.
		$freno = 'abh_core_pkg_fail_' . md5( $version . '|' . $locale );
		if ( get_transient( $freno ) ) {
			return false;
		}

		// Este plugin trabaja precisamente sobre instalaciones rotas: si ese
		// archivo del núcleo falta, hay que rendirse aquí, no lanzar un fatal.
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
		foreach ( self::package_urls( $version, $locale ) as $url ) {
			$tmp = download_url( $url, 180 );
			if ( is_wp_error( $tmp ) ) {
				continue;
			}
			if ( filesize( $tmp ) < 1048576 || ! self::looks_like_wp_zip( $tmp ) ) {
				@unlink( $tmp );
				continue;
			}
			if ( @rename( $tmp, $destino ) ) {
				@chmod( $destino, 0600 );
				return $destino;
			}
			@unlink( $tmp );
		}

		set_transient( $freno, 1, 10 * MINUTE_IN_SECONDS );
		return false;
	}

	/**
	 * Comprueba que un zip descargado sea de verdad un paquete de WordPress.
	 *
	 * @param string $zip Ruta.
	 * @return bool
	 */
	private static function looks_like_wp_zip( $zip ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return false;
		}
		$za = new ZipArchive();
		if ( true !== $za->open( $zip ) ) {
			return false;
		}
		$ok = false !== $za->locateName( 'wordpress/wp-includes/version.php' );
		$za->close();
		return $ok;
	}

	/**
	 * Extrae un archivo del paquete oficial y verifica su huella.
	 *
	 * @param string $rel     Ruta relativa.
	 * @param string $version Versión.
	 * @param string $locale  Idioma.
	 * @return string|false
	 */
	public static function package_file( $rel, $version, $locale ) {
		$sumas = self::checksums( $version, $locale );
		if ( ! is_array( $sumas ) || ! isset( $sumas[ $rel ] ) ) {
			return false;
		}
		$zip = self::ensure_package( $version, $locale );
		if ( ! $zip || ! class_exists( 'ZipArchive' ) ) {
			return false;
		}
		$za = new ZipArchive();
		if ( true !== $za->open( $zip ) ) {
			return false;
		}
		$cuerpo = $za->getFromName( 'wordpress/' . $rel );
		$za->close();
		if ( false === $cuerpo ) {
			return false;
		}
		// La huella manda también aquí: el paquete no es una excepción.
		if ( ! hash_equals( (string) $sumas[ $rel ], md5( $cuerpo ) ) ) {
			return false;
		}
		return $cuerpo;
	}

	/**
	 * Estado de un archivo concreto frente al oficial, sin escanear todo.
	 *
	 * Solo usa las huellas ya cacheadas: no dispara descargas al pintar la
	 * página. Si aún no hay caché, lo dice y la comprobación se pide aparte.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	public static function file_status( $rel ) {
		$rel   = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		$fuera = array( 'is_core' => false, 'known' => false, 'altered' => false, 'accepted' => false, 'missing' => false );
		if ( '' === $rel || false !== strpos( $rel, '..' ) || 'wp-config.php' === $rel || 0 === strpos( $rel, 'wp-content/' ) ) {
			return $fuera;
		}

		$version = self::installed_version();
		$locale  = get_locale();
		$sumas   = get_transient( 'abh_core_sums_' . md5( $version . '|' . $locale ) );
		if ( ! is_array( $sumas ) ) {
			// Sin huellas cacheadas no afirmamos nada: solo que la ruta cae
			// dentro del núcleo por su forma.
			$parece = ( 0 === strpos( $rel, 'wp-includes/' ) || 0 === strpos( $rel, 'wp-admin/' ) );
			return array( 'is_core' => $parece, 'known' => false, 'altered' => false, 'accepted' => false, 'missing' => false );
		}
		if ( ! isset( $sumas[ $rel ] ) ) {
			return $fuera;
		}

		$abs = self::core_path( $rel );
		if ( ! $abs ) {
			return $fuera;
		}
		if ( ! file_exists( $abs ) ) {
			return array( 'is_core' => true, 'known' => true, 'altered' => false, 'accepted' => false, 'missing' => true );
		}
		$md5       = (string) @md5_file( $abs );
		$aceptados = self::accepted();
		$alterado  = ! hash_equals( (string) $sumas[ $rel ], $md5 );
		return array(
			'is_core'  => true,
			'known'    => true,
			'altered'  => $alterado,
			'accepted' => $alterado && isset( $aceptados[ $rel ] ) && hash_equals( (string) $aceptados[ $rel ], $md5 ),
			'missing'  => false,
		);
	}

	/**
	 * Último escaneo de integridad completado.
	 *
	 * @return array|false
	 */
	public static function last_scan() {
		$s = get_option( self::LAST_SCAN, false );
		if ( ! is_array( $s ) || ! isset( $s['modified'] ) ) {
			return false;
		}
		$s['modified'] = is_array( $s['modified'] ) ? $s['modified'] : array();
		$s['missing']  = isset( $s['missing'] ) && is_array( $s['missing'] ) ? $s['missing'] : array();
		$s['accepted'] = isset( $s['accepted'] ) && is_array( $s['accepted'] ) ? $s['accepted'] : array();
		return $s;
	}

	/**
	 * Encuentra qué archivo del núcleo debería definir una función que falta.
	 *
	 * Un «Call to undefined function» apunta al archivo que la LLAMA, no al que
	 * debería definirla. Quien llama suele estar intacto y quien la define es el
	 * que está roto, así que señalar al primero manda a la persona a mirar el
	 * sitio equivocado.
	 *
	 * Esto no adivina: para cada archivo del núcleo que el escaneo marcó como
	 * alterado o faltante, compara el original oficial con lo instalado. Si el
	 * oficial define la función y tu copia no, ahí está la causa, demostrada.
	 * Cero tokens.
	 *
	 * @param string $fn Nombre de la función ausente.
	 * @return array|false
	 */
	public static function blame_undefined_function( $fn ) {
		$fn = trim( (string) $fn );
		if ( '' === $fn || ! preg_match( '/^[A-Za-z_][A-Za-z0-9_]*$/', $fn ) ) {
			return false;
		}
		// Vía directa: el índice del paquete oficial sabe qué archivo debería
		// definirla, sin depender de que se haya corrido el escaneo completo.
		$definidor = self::defining_file( $fn );
		if ( '' !== $definidor ) {
			$abs    = self::core_path( $definidor );
			$actual = ( $abs && file_exists( $abs ) ) ? (string) @file_get_contents( $abs ) : '';
			$define = '' !== $actual && preg_match( '/^function\s+&?\s*' . preg_quote( $fn, '/' ) . '\s*\(/mi', $actual );
			if ( ! $define ) {
				return array(
					'ok'        => true,
					'need_scan' => false,
					'function'  => $fn,
					'rel_path'  => $definidor,
					'faltante'  => '' === $actual,
					'source'    => 'indice',
					'message'   => '' === $actual
						? sprintf(
							/* translators: 1: función, 2: ruta. */
							__( 'Function %1$s is defined by WordPress in %2$s, and that file is missing from your installation. That is the cause: the file in the error was only calling it.', 'ai-bug-hunter' ),
							$fn,
							$definidor
						)
						: sprintf(
							/* translators: 1: función, 2: ruta. */
							__( 'Function %1$s is defined by WordPress in %2$s. Your copy of that file no longer defines it, which is why the caller fails. That is the cause, not the file in the error.', 'ai-bug-hunter' ),
							$fn,
							$definidor
						),
				);
			}
			// El archivo sí la define: entonces no se está cargando, y eso ya
			// no es un problema de integridad del núcleo.
			return array(
				'ok'        => false,
				'need_scan' => false,
				'loaded'    => false,
				'rel_path'  => $definidor,
				'message'   => sprintf(
					/* translators: 1: función, 2: ruta. */
					__( '%2$s does define %1$s, so the file is fine: what fails is the load order. Something uses that function before WordPress gets to define it. Look in this order: a mu-plugin (they load before everything else), a plugin that runs code in the global scope or hooks in with a very early priority, and above all an auto_prepend_file in .htaccess or php.ini, which runs BEFORE WordPress starts up. That last one HUNTER AI cannot see: it never reads or modifies .htaccess.', 'ai-bug-hunter' ),
					$fn,
					$definidor
				),
			);
		}

		$escaneo = self::last_scan();
		if ( ! $escaneo ) {
			return array( 'ok' => false, 'need_scan' => true );
		}

		$sospechosos = array_merge( $escaneo['modified'], $escaneo['missing'], $escaneo['accepted'] );
		if ( empty( $sospechosos ) ) {
			return array( 'ok' => false, 'need_scan' => false );
		}

		// El veredicto se cachea: repetirlo obligaría a bajar los mismos
		// archivos oficiales en cada carga de la página.
		$clave  = 'abh_core_blame_' . md5( strtolower( $fn ) . '|' . implode( ',', $sospechosos ) );
		$guarda = get_transient( $clave );
		if ( is_array( $guarda ) ) {
			return $guarda;
		}

		$patron = '/function\s+&?\s*' . preg_quote( $fn, '/' ) . '\s*\(/i';
		foreach ( array_slice( $sospechosos, 0, 25 ) as $rel ) {
			if ( ! preg_match( '/\.php$/i', $rel ) ) {
				continue;
			}
			$oficial = self::official_file( $rel );
			if ( false === $oficial || ! preg_match( $patron, $oficial ) ) {
				continue;
			}
			// El oficial sí la define. ¿Y tu copia?
			$abs    = self::core_path( $rel );
			$actual = ( $abs && file_exists( $abs ) ) ? (string) @file_get_contents( $abs ) : '';
			if ( '' !== $actual && preg_match( $patron, $actual ) ) {
				continue;
			}

			$veredicto = array(
				'ok'        => true,
				'need_scan' => false,
				'function'  => $fn,
				'rel_path'  => $rel,
				'faltante'  => '' === $actual,
				'message'   => '' === $actual
					? sprintf(
						/* translators: 1: función, 2: ruta. */
						__( 'Function %1$s is defined in %2$s, and that file is missing from your installation. That is the cause, not the file that appears in the error.', 'ai-bug-hunter' ),
						$fn,
						$rel
					)
					: sprintf(
						/* translators: 1: función, 2: ruta. */
						__( 'Function %1$s should be defined in %2$s. Official WordPress defines it there; your copy of that file does not. That is the cause: the file in the error was only calling it.', 'ai-bug-hunter' ),
						$fn,
						$rel
					),
			);
			set_transient( $clave, $veredicto, HOUR_IN_SECONDS );
			return $veredicto;
		}

		$nada = array( 'ok' => false, 'need_scan' => false );
		set_transient( $clave, $nada, 15 * MINUTE_IN_SECONDS );
		return $nada;
	}

	/**
	 * Índice «función => archivo que la define» del WordPress oficial.
	 *
	 * Se construye una sola vez por versión e idioma, recorriendo el paquete
	 * oficial que ya está en el repertorio, y se guarda junto a él. A partir de
	 * ahí, saber qué archivo debería definir cualquier función del núcleo es
	 * instantáneo: sin red, sin escaneo previo y sin tokens.
	 *
	 * @param string $version Versión.
	 * @param string $locale  Idioma.
	 * @return array|false Mapa nombre en minúsculas => ruta relativa.
	 */
	public static function function_index( $version = '', $locale = '' ) {
		$version = '' !== $version ? $version : self::installed_version();
		$locale  = '' !== $locale ? $locale : get_locale();
		$dir     = self::cache_dir();
		if ( ! $dir || '' === $version ) {
			return false;
		}
		if ( ! preg_match( '/^[0-9][0-9.]{0,15}$/', $version ) || ! preg_match( '/^[A-Za-z0-9_]{2,12}$/', $locale ) ) {
			return false;
		}

		$archivo = $dir . '/functions-' . $version . '-' . $locale . '.json';
		if ( is_file( $archivo ) ) {
			$datos = json_decode( (string) @file_get_contents( $archivo ), true );
			if ( is_array( $datos ) && ! empty( $datos ) ) {
				return $datos;
			}
		}

		// Construirlo es caro: que no lo hagan dos peticiones a la vez.
		$cerrojo = 'abh_core_fnidx_' . md5( $version . '|' . $locale );
		if ( get_transient( $cerrojo ) ) {
			return false;
		}
		set_transient( $cerrojo, 1, 5 * MINUTE_IN_SECONDS );

		$zip = self::ensure_package( $version, $locale );
		if ( ! $zip || ! class_exists( 'ZipArchive' ) ) {
			delete_transient( $cerrojo );
			return false;
		}
		$za = new ZipArchive();
		if ( true !== $za->open( $zip ) ) {
			delete_transient( $cerrojo );
			return false;
		}

		$indice = array();
		for ( $i = 0; $i < $za->numFiles; $i++ ) {
			$nombre = (string) $za->getNameIndex( $i );
			if ( 0 !== strpos( $nombre, 'wordpress/' ) || ! preg_match( '/\.php$/i', $nombre ) ) {
				continue;
			}
			$rel = substr( $nombre, 10 );
			// Solo el núcleo: wp-content trae temas por defecto que no cuentan.
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				continue;
			}
			$cuerpo = $za->getFromIndex( $i );
			if ( false === $cuerpo || '' === $cuerpo ) {
				continue;
			}
			// Solo funciones de nivel superior: los métodos de clase van
			// sangrados y no se pueden llamar sueltos, así que no aplican.
			if ( ! preg_match_all( '/^function\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/mi', $cuerpo, $mm ) ) {
				continue;
			}
			foreach ( $mm[1] as $fn ) {
				$clave = strtolower( $fn );
				if ( ! isset( $indice[ $clave ] ) ) {
					$indice[ $clave ] = $rel;
				}
			}
		}
		$za->close();
		delete_transient( $cerrojo );

		if ( empty( $indice ) ) {
			return false;
		}
		$json = wp_json_encode( $indice );
		if ( false !== $json ) {
			$tmp = $archivo . '.tmp';
			if ( false !== @file_put_contents( $tmp, $json ) ) {
				@chmod( $tmp, 0600 );
				@rename( $tmp, $archivo );
			}
		}
		return $indice;
	}

	/**
	 * Archivo del núcleo que debería definir una función.
	 *
	 * @param string $fn Nombre de la función.
	 * @return string Ruta relativa, o cadena vacía.
	 */
	public static function defining_file( $fn ) {
		$indice = self::function_index();
		if ( ! is_array( $indice ) ) {
			return '';
		}
		$clave = strtolower( (string) $fn );
		return isset( $indice[ $clave ] ) ? $indice[ $clave ] : '';
	}

	/**
	 * Extrae el nombre de la función ausente de un mensaje de error.
	 *
	 * @param string $msg Mensaje.
	 * @return string
	 */
	public static function undefined_function_in( $msg ) {
		if ( preg_match( '/Call to undefined function\s+(?:[\\\\\w]+\\\\)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/i', (string) $msg, $m ) ) {
			return $m[1];
		}
		return '';
	}
}
