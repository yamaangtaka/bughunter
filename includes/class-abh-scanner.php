<?php
/**
 * Escáner sintáctico WordPress-first.
 *
 * Revisa archivos PHP sin ejecutarlos. Usa el parser interno de PHP para
 * detectar errores que pueden ocurrir antes de que WordPress alcance a escribir
 * debug.log, como un wp-login.php dañado.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Recorre el árbol del sitio buscando archivos que analizar.
 *
 * POR QUE EXISTE:  Barrer entero es lo que permite encontrar lo que el registro no cuenta.
 *
 * SI LO RECORTAS:  Lo que encuentra son datos. Un nombre de archivo o un fragmento de código nunca cambia lo que hace el plugin.
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
 * Class ABH_Scanner
 */
class ABH_Scanner {

	const TTL            = 1800;
	const BATCH_SIZE     = 24;
	const MAX_FILES      = 15000;
	const MAX_FILE_BYTES = 4194304;
	const REPORT_OPTION  = 'abh_last_syntax_scan';

	/**
	 * Inicia un escaneo y congela el listado de archivos en un transient cifrado.
	 *
	 * @param string $scope quick|full.
	 * @return array
	 */
	public static function start( $scope = 'quick' ) {
		$scope = in_array( $scope, array( 'quick', 'full' ), true ) ? $scope : 'quick';
		$files = self::inventory( $scope );
		$id    = 'SCAN-' . gmdate( 'Ymd-His' ) . '-' . strtoupper( wp_generate_password( 6, false, false ) );
		$state = array(
			'scan_id'    => $id,
			'user_id'    => get_current_user_id(),
			'scope'      => $scope,
			'files'      => $files,
			'cursor'     => 0,
			'scanned'    => 0,
			'findings'   => array(),
			'skipped'    => array(),
			'started_at' => time(),
		);

		if ( ! self::store( $state ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'I could not create an encrypted session for the scan.', 'ai-bug-hunter' ),
			);
		}

		return array(
			'ok'      => true,
			'scan_id' => $id,
			'scope'   => $scope,
			'total'   => count( $files ),
			'message' => __( 'File map frozen. The scan can continue in blocks without executing the code.', 'ai-bug-hunter' ),
		);
	}

	/**
	 * Procesa el siguiente bloque de archivos.
	 *
	 * @param string $scan_id Identificador.
	 * @return array
	 */
	public static function step( $scan_id ) {
		$state = self::load( $scan_id );
		if ( ! is_array( $state ) ) {
			return self::error( __( 'The scan session expired. Start a new one.', 'ai-bug-hunter' ) );
		}
		if ( (int) $state['user_id'] !== get_current_user_id() ) {
			return self::error( __( 'This scan belongs to another administrator.', 'ai-bug-hunter' ) );
		}

		$total = count( $state['files'] );
		$end   = min( $total, (int) $state['cursor'] + self::BATCH_SIZE );

		for ( $i = (int) $state['cursor']; $i < $end; $i++ ) {
			$rel = isset( $state['files'][ $i ] ) ? ABH_Guard::normalize( $state['files'][ $i ] ) : '';
			if ( '' === $rel ) {
				continue;
			}
			$abs = ABH_Guard::resolve_existing_path( $rel, null );
			if ( ! $abs || is_link( $abs ) || ! is_file( $abs ) || ! is_readable( $abs ) ) {
				$state['skipped'][] = array(
					'rel_path' => $rel,
					'reason'   => 'unreadable',
				);
				continue;
			}

			$size = @filesize( $abs );
			if ( false !== $size && $size > self::MAX_FILE_BYTES ) {
				$state['skipped'][] = array(
					'rel_path' => $rel,
					'reason'   => 'too_large',
				);
				continue;
			}

			$code = @file_get_contents( $abs );
			if ( false === $code ) {
				$state['skipped'][] = array(
					'rel_path' => $rel,
					'reason'   => 'read_failed',
				);
				continue;
			}

			$state['scanned']++;
			$result = self::parse_php( $code );
			if ( ! empty( $result['error'] ) ) {
				$state['findings'][] = self::finding( $rel, $result, $code );
			}
		}

		$state['cursor'] = $end;
		$done            = $end >= $total;
		if ( $done ) {
			$report = self::finish( $state );
			delete_transient( self::key( $scan_id ) );
			return array(
				'ok'       => true,
				'done'     => true,
				'progress' => 100,
				'report'   => $report,
			);
		}

		if ( ! self::store( $state ) ) {
			return self::error( __( 'I could not save the encrypted scan progress.', 'ai-bug-hunter' ) );
		}

		return array(
			'ok'        => true,
			'done'      => false,
			'progress'  => $total > 0 ? (int) floor( ( $end / $total ) * 100 ) : 100,
			'cursor'    => $end,
			'total'     => $total,
			'scanned'   => (int) $state['scanned'],
			'found'     => count( $state['findings'] ),
			'last_path' => $end > 0 ? $state['files'][ $end - 1 ] : '',
		);
	}

	/**
	 * Último reporte persistido.
	 *
	 * @return array
	 */
	public static function last_report() {
		$report = get_option( self::REPORT_OPTION, array() );
		return is_array( $report ) ? $report : array();
	}

	/**
	 * Los hallazgos que SIGUEN siendo ciertos ahora mismo.
	 *
	 * El reporte del escáner es una foto: se guardaba en una opción y se pintaba
	 * tal cual hasta el siguiente escaneo. El dueño arreglaba el archivo y la
	 * tarjeta seguía ahí, con su botón de reparar, invitando a gastar tokens en
	 * un archivo que ya compila. Caso real: form-pay.php:86 mostrándose quince
	 * horas después de que el archivo volviera a estar bien.
	 *
	 * Aquí se relee cada archivo señalado y se le pregunta a PHP. Si compila, la
	 * foto es vieja y el hallazgo no se pinta. Cero red, cero tokens, cero
	 * dependencia de la fecha de modificación.
	 *
	 * @param array $report Reporte del escáner.
	 * @return array Hallazgos vigentes.
	 */
	public static function fresh_findings( $report ) {
		if ( empty( $report['findings'] ) || ! is_array( $report['findings'] ) ) {
			return array();
		}
		if ( ! class_exists( 'ABH_Engine' ) || ! class_exists( 'ABH_Verifier' ) ) {
			return array_values( $report['findings'] );
		}

		$vigentes = array();
		foreach ( $report['findings'] as $hallazgo ) {
			$rel = isset( $hallazgo['rel_path'] ) ? (string) $hallazgo['rel_path'] : '';
			if ( '' === $rel ) {
				$vigentes[] = $hallazgo;
				continue;
			}
			$codigo = ABH_Engine::read_file( $rel );
			if ( false === $codigo || '' === $codigo ) {
				// No se pudo releer: se conserva. Callar un hallazgo por no
				// haberlo podido comprobar sería peor que mostrarlo de más.
				$vigentes[] = $hallazgo;
				continue;
			}
			$lint = ABH_Verifier::lint( $codigo );
			// Sin el analizador real no se declara nada resuelto: el respaldo
			// heurístico cuenta llaves y da por bueno un archivo roto.
			if ( ! isset( $lint['method'] ) || 'token_get_all' !== $lint['method'] ) {
				$vigentes[] = $hallazgo;
				continue;
			}
			if ( empty( $lint['ok'] ) ) {
				$vigentes[] = $hallazgo;
			}
		}
		return $vigentes;
	}

	/**
	 * Busca un hallazgo sintáctico por clave.
	 *
	 * @param string $key Clave.
	 * @return array|false
	 */
	public static function get_finding( $key ) {
		$report = self::last_report();
		if ( empty( $report['findings'] ) || ! is_array( $report['findings'] ) ) {
			return false;
		}
		foreach ( $report['findings'] as $finding ) {
			if ( isset( $finding['key'] ) && hash_equals( (string) $finding['key'], (string) $key ) ) {
				return $finding;
			}
		}
		return false;
	}

	/**
	 * Devuelve una incidencia desde logs o desde el escaneo estático.
	 *
	 * @param string $key Clave.
	 * @return array|false
	 */
	public static function get_incident( $key ) {
		$incident = ABH_Logs::get_incident( $key );
		return $incident ? $incident : self::get_finding( $key );
	}

	/**
	 * Analiza sintaxis sin ejecutar el archivo.
	 *
	 * @param string $code Código.
	 * @return array
	 */
	public static function parse_php( $code ) {
		if ( ! function_exists( 'token_get_all' ) || ! defined( 'TOKEN_PARSE' ) ) {
			return array(
				'error'   => true,
				'line'    => 0,
				'message' => __( 'The PHP parser is not available on this server.', 'ai-bug-hunter' ),
				'code'    => 'ABH-SCAN-002',
			);
		}

		try {
			token_get_all( (string) $code, TOKEN_PARSE );
			return array(
				'error'   => false,
				'line'    => 0,
				'message' => '',
				'code'    => '',
			);
		} catch ( ParseError $e ) {
			return array(
				'error'   => true,
				'line'    => max( 1, (int) $e->getLine() ),
				'message' => self::clean_parse_message( $e->getMessage() ),
				'code'    => 'ABH-SCAN-001',
			);
		} catch ( Throwable $e ) {
			return array(
				'error'   => true,
				'line'    => max( 0, (int) $e->getLine() ),
				'message' => self::clean_parse_message( $e->getMessage() ),
				'code'    => 'ABH-SCAN-002',
			);
		}
	}

	/**
	 * Inventario de archivos PHP.
	 *
	 * quick: raíz de WordPress + wp-content.
	 * full: añade wp-admin y wp-includes.
	 *
	 * @param string $scope Alcance.
	 * @return array
	 */
	public static function inventory( $scope = 'quick' ) {
		$files     = array();
		$root_real = realpath( ABSPATH );
		if ( false === $root_real ) {
			return array();
		}
		$root = rtrim( wp_normalize_path( $root_real ), '/' );

		$top = @scandir( $root );
		if ( is_array( $top ) ) {
			foreach ( $top as $name ) {
				if ( '.' === $name || '..' === $name || '.php' !== strtolower( substr( $name, -4 ) ) ) {
					continue;
				}
				$abs = $root . '/' . $name;
				if ( is_file( $abs ) && ! is_link( $abs ) ) {
					$files[] = $name;
				}
			}
		}

		$roots = array(
			'wp-content/plugins',
			'wp-content/themes',
			'wp-content/mu-plugins',
		);
		if ( 'full' === $scope ) {
			$roots[] = 'wp-admin';
			$roots[] = 'wp-includes';
		}

		foreach ( $roots as $rel_root ) {
			self::walk( $root . '/' . $rel_root, $root, $files, 0 );
			if ( count( $files ) >= self::MAX_FILES ) {
				break;
			}
		}

		$files = array_values( array_unique( $files ) );
		sort( $files, SORT_STRING );
		if ( count( $files ) > self::MAX_FILES ) {
			$files = array_slice( $files, 0, self::MAX_FILES );
		}
		return $files;
	}

	/**
	 * Recorrido seguro sin seguir enlaces simbólicos.
	 *
	 * @param string $dir   Directorio actual.
	 * @param string $root  Raíz WordPress.
	 * @param array  $files Acumulador.
	 * @param int    $depth Profundidad.
	 * @return void
	 */
	private static function walk( $dir, $root, &$files, $depth ) {
		if ( $depth > 30 || count( $files ) >= self::MAX_FILES || ! is_dir( $dir ) || is_link( $dir ) ) {
			return;
		}
		$real = realpath( $dir );
		if ( false === $real || ! ABH_Guard::absolute_in_root( wp_normalize_path( $real ), $root ) ) {
			return;
		}
		$items = @scandir( $real );
		if ( ! is_array( $items ) ) {
			return;
		}
		foreach ( $items as $name ) {
			if ( '.' === $name || '..' === $name || count( $files ) >= self::MAX_FILES ) {
				continue;
			}
			$abs = wp_normalize_path( $real . '/' . $name );
			if ( is_link( $abs ) ) {
				continue;
			}
			if ( is_dir( $abs ) ) {
				self::walk( $abs, $root, $files, $depth + 1 );
				continue;
			}
			if ( is_file( $abs ) && '.php' === strtolower( substr( $name, -4 ) ) && ABH_Guard::absolute_in_root( $abs, $root ) ) {
				$files[] = ltrim( substr( $abs, strlen( $root ) ), '/' );
			}
		}
	}

	/**
	 * Crea una incidencia compatible con HUNTER AI.
	 *
	 * @param string $rel    Ruta.
	 * @param array  $result Resultado parser.
	 * @param string $code   Código completo, usado solo para hash.
	 * @return array
	 */
	private static function finding( $rel, $result, $code ) {
		$key = 'syntax-' . md5( $rel . '|' . (int) $result['line'] . '|' . $result['message'] . '|' . hash( 'sha256', $code ) );
		return array(
			'key'       => $key,
			'kind'      => 'Parse error',
			'message'   => (string) $result['message'],
			'short'     => (string) $result['message'],
			'file'      => wp_normalize_path( ABSPATH . $rel ),
			'rel_path'  => $rel,
			'line'      => (int) $result['line'],
			'count'     => 1,
			'first_ts'  => gmdate( 'd-M-Y H:i:s' ) . ' UTC',
			'last_ts'   => gmdate( 'd-M-Y H:i:s' ) . ' UTC',
			'last_unix' => time(),
			'severity'  => 100,
			'source'    => 'syntax_scan',
			'scan_code' => isset( $result['code'] ) ? $result['code'] : 'ABH-SCAN-001',
			'core_file' => self::is_core_file( $rel ),
		);
	}

	/**
	 * Cierra y persiste el reporte, sin guardar código fuente.
	 *
	 * @param array $state Estado.
	 * @return array
	 */
	private static function finish( $state ) {
		$report = array(
			'scan_id'     => $state['scan_id'],
			'scope'       => $state['scope'],
			'total'       => count( $state['files'] ),
			'scanned'     => (int) $state['scanned'],
			'findings'    => array_values( $state['findings'] ),
			'skipped'     => array_slice( array_values( $state['skipped'] ), 0, 100 ),
			'completed_at'=> time(),
			'duration'    => max( 0, time() - (int) $state['started_at'] ),
		);
		update_option( self::REPORT_OPTION, $report, false );
		return $report;
	}

	/**
	 * ¿Es archivo del núcleo o raíz protegida?
	 *
	 * @param string $rel Ruta.
	 * @return bool
	 */
	public static function is_core_file( $rel ) {
		$rel = ABH_Guard::normalize( $rel );
		if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
			return true;
		}
		return 0 !== strpos( $rel, 'wp-content/' );
	}

	/**
	 * Limpia mensajes para que no filtren rutas absolutas.
	 *
	 * @param string $message Mensaje.
	 * @return string
	 */
	private static function clean_parse_message( $message ) {
		$message = preg_replace( '/\s+in\s+[^\s]+\s+on\s+line\s+\d+$/i', '', (string) $message );
		return sanitize_text_field( $message );
	}

	private static function key( $scan_id ) {
		return 'abh_scan_' . sanitize_key( $scan_id );
	}

	private static function store( $state ) {
		$json = wp_json_encode( $state );
		$enc  = ABH_Crypto::encrypt( $json, 'syntax-scan' );
		return false !== $enc && set_transient( self::key( $state['scan_id'] ), $enc, self::TTL );
	}

	private static function load( $scan_id ) {
		$enc = get_transient( self::key( $scan_id ) );
		if ( ! ABH_Crypto::is_encrypted( $enc ) ) {
			return false;
		}
		$json = ABH_Crypto::decrypt( $enc, 'syntax-scan' );
		$data = false !== $json ? json_decode( $json, true ) : null;
		return is_array( $data ) ? $data : false;
	}

	private static function error( $message ) {
		return array(
			'ok'      => false,
			'message' => $message,
		);
	}
}
