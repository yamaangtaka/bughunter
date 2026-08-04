<?php
/**
 * EL MOTOR — Capa 0 del diagnóstico. Conocimiento propio, cero tokens.
 *
 * Muchos errores del registro NO son errores de código: son problemas del
 * entorno (permisos, memoria, tiempo de ejecución, núcleo incompleto,
 * extensiones ausentes, disco lleno). Para esos, parchear el PHP es tapar el
 * síntoma: el problema real sigue ahí.
 *
 * Este motor los reconoce por su firma y, en lugar de adivinar desde el texto
 * del registro, le pregunta al sistema de archivos: qué permisos tiene el
 * archivo, quién es su dueño, como qué usuario corre PHP, si el archivo del
 * núcleo existe, cuánta memoria hay configurada. Con eso da un diagnóstico
 * exacto, instantáneo y sin gastar un solo token de IA.
 *
 * Lo que este motor no reconoce, pasa a la IA. Esa es la Capa 1.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Cambia permisos de archivos y carpetas para reparar problemas de entorno.
 *
 * POR QUE EXISTE:  Un archivo en 0000 no lo puede tocar quien no tiene FTP. Ahí sólo puede el plugin, y por eso la capacidad existe.
 *
 * SI LO RECORTAS:  Restringir los modos octales quita el caso de más valor: el sitio de un cliente que no tiene acceso al hosting.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Syntax checks use restrictive local temporary files and native handles required by the PHP parser workflow.

/**
 * Class ABH_Motor
 */
class ABH_Motor {

	/**
	 * Etiqueta honesta para el historial: esto NO lo resolvió un modelo de IA.
	 */
	const SIGNATURE = 'motor-abh/v1';

	/**
	 * Permisos a los que se normaliza al corregir. Nunca más permisivos.
	 */
	const MODE_PRIVATE_FILE = 0600;
	const MODE_FILE         = 0644;
	const MODE_DIR          = 0755;

	/**
	 * Catálogo público de diagnósticos del motor.
	 *
	 * @return array
	 */
	public static function catalog() {
		return array(
			'ABH-ENV-001' => array(
				'titulo'      => __( 'Insufficient permissions on a file', 'ai-bug-hunter' ),
				'explicacion' => __( 'PHP cannot read or write a file because of its permissions or its owner. This is not a programming error: patching the code only hides the warning.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-002' => array(
				'titulo'      => __( 'Folder is not writable', 'ai-bug-hunter' ),
				'explicacion' => __( 'PHP cannot create files inside a folder. This affects uploads, caches and logs.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-003' => array(
				'titulo'      => __( 'File or folder that does not exist', 'ai-bug-hunter' ),
				'explicacion' => __( 'The code is looking for something that is not on disk. It usually means an incomplete installation or a deleted file.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-004' => array(
				'titulo'      => __( 'PHP memory exhausted', 'ai-bug-hunter' ),
				'explicacion' => __( 'The process asked for more memory than allowed. It is solved by raising the limit, not by touching the code.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-005' => array(
				'titulo'      => __( 'Execution time exceeded', 'ai-bug-hunter' ),
				'explicacion' => __( 'The process took longer than allowed and the server cut it off.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-006' => array(
				'titulo'      => __( 'Incomplete WordPress core', 'ai-bug-hunter' ),
				'explicacion' => __( 'A file that belongs to WordPress itself is missing. This happens after an interrupted update or an incomplete FTP upload. It is fixed by reinstalling the core, never by patching code.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-007' => array(
				'titulo'      => __( 'PHP extension missing', 'ai-bug-hunter' ),
				'explicacion' => __( 'The code uses a function that lives in an extension your server does not have enabled. Your hosting is the one that enables it.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-008' => array(
				'titulo'      => __( 'No space left on disk', 'ai-bug-hunter' ),
				'explicacion' => __( 'The server ran out of space. Until some is freed, nothing that writes to disk will work.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-009' => array(
				'titulo'      => __( 'A constant defined twice', 'ai-bug-hunter' ),
				'explicacion' => __( 'There are two lines defining the same configuration value. PHP keeps the first, ignores the second and leaves a notice every time. The site works; what fills up is the log.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-010' => array(
				'titulo'      => __( 'A plugin loads its translations too early', 'ai-bug-hunter' ),
				'explicacion' => __( 'WordPress warns when a plugin or theme asks for its translations too early. The core file that shows up in the log is only the messenger: the one who has to fix it is the author of the plugin named. The site keeps working.', 'ai-bug-hunter' ),
			),
			'ABH-ENV-011' => array(
				'titulo'      => __( 'An empty value reaches a core function', 'ai-bug-hunter' ),
				'explicacion' => __( 'PHP 8.1 warns when an empty value is passed where text is expected. The core file where the warning appears is not the culprit: the culprit is whoever passed that empty value.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Usuario con el que corre PHP.
	 *
	 * @return string
	 */
	public static function php_user() {
		if ( function_exists( 'posix_geteuid' ) && function_exists( 'posix_getpwuid' ) ) {
			$u = @posix_getpwuid( @posix_geteuid() );
			if ( ! empty( $u['name'] ) ) {
				return $u['name'];
			}
		}
		$fallback = function_exists( 'get_current_user' ) ? @get_current_user() : '';
		return '' !== $fallback ? $fallback : __( 'not identifiable', 'ai-bug-hunter' );
	}

	/**
	 * Identificador numérico del usuario de PHP, o false si no se puede saber.
	 *
	 * @return int|false
	 */
	public static function php_uid() {
		if ( function_exists( 'posix_geteuid' ) ) {
			return @posix_geteuid();
		}
		return false;
	}

	/**
	 * Nombre del dueño de un archivo.
	 *
	 * @param int|false $uid Identificador.
	 * @return string
	 */
	private static function owner_name( $uid ) {
		if ( false === $uid ) {
			return '';
		}
		if ( function_exists( 'posix_getpwuid' ) ) {
			$u = @posix_getpwuid( $uid );
			if ( ! empty( $u['name'] ) ) {
				return $u['name'];
			}
		}
		return (string) $uid;
	}

	/**
	 * Radiografía real de una ruta: lo que el sistema de archivos dice de ella.
	 *
	 * @param string $path Ruta absoluta.
	 * @return array
	 */
	public static function inspect( $path ) {
		$out = array(
			'path'            => $path,
			'exists'          => false,
			'is_dir'          => false,
			'perms'           => '',
			'owner'           => '',
			'owner_uid'       => false,
			'readable'        => false,
			'writable'        => false,
			'parent'          => '',
			'parent_exists'   => false,
			'parent_writable' => false,
			'we_own_it'       => false,
		);

		if ( '' === $path ) {
			return $out;
		}

		$out['exists'] = @file_exists( $path );

		if ( $out['exists'] ) {
			$out['is_dir']   = @is_dir( $path );
			$perms           = @fileperms( $path );
			$out['perms']    = ( false !== $perms ) ? substr( sprintf( '%o', $perms ), -4 ) : '';
			$uid             = @fileowner( $path );
			$out['owner_uid'] = $uid;
			$out['owner']    = self::owner_name( $uid );
			$out['readable'] = @is_readable( $path );
			$out['writable'] = @is_writable( $path );

			$php_uid = self::php_uid();
			$out['we_own_it'] = ( false !== $php_uid && false !== $uid && (int) $php_uid === (int) $uid );
		}

		$out['parent']          = dirname( $path );
		$out['parent_exists']   = @is_dir( $out['parent'] );
		$out['parent_writable'] = $out['parent_exists'] ? @is_writable( $out['parent'] ) : false;

		return $out;
	}

	/**
	 * Extrae del mensaje del registro la ruta implicada.
	 *
	 * @param string $msg Mensaje.
	 * @return string
	 */
	public static function extract_path( $msg ) {
		$patterns = array(
			'/\b(?:fopen|file_get_contents|file_put_contents|unlink|mkdir|rmdir|touch|copy|rename|scandir|opendir|fwrite|readfile|move_uploaded_file)\s*\(\s*([^,)]+?)\s*[,)]/i',
			'/stat failed for\s+(.+?)(?:\s+in\s+\S+\.php|$)/i',
			'/Failed opening\s+[\'"]?(.+?)[\'"]?\s+for inclusion/i',
			'/(?:include|require)(?:_once)?\s*\(\s*[\'"]?(.+?)[\'"]?\s*\)/i',
			'/failed to open stream[^:]*:\s*.*?\bin\s+(\S+\.php)/i',
		);

		foreach ( $patterns as $rx ) {
			if ( preg_match( $rx, $msg, $m ) ) {
				$p = trim( $m[1] );
				$p = trim( $p, "'\" \t" );
				if ( '' !== $p && false === strpos( $p, '$' ) ) {
					$p = wp_normalize_path( $p );
					// Limpia los «/./» que dejan algunas configuraciones.
					$p = preg_replace( '#/\./#', '/', $p );
					return (string) $p;
				}
			}
		}
		return '';
	}

	/**
	 * Convierte bytes en algo legible.
	 *
	 * @param int $bytes Bytes.
	 * @return string
	 */
	private static function human_bytes( $bytes ) {
		$bytes = (int) $bytes;
		if ( $bytes >= 1048576 ) {
			return round( $bytes / 1048576 ) . ' MB';
		}
		if ( $bytes >= 1024 ) {
			return round( $bytes / 1024 ) . ' KB';
		}
		return $bytes . ' B';
	}

	/**
	 * Ruta relativa a la raíz de WordPress, para mostrar y para el historial.
	 *
	 * @param string $abs Ruta absoluta.
	 * @return string
	 */
	public static function rel_of( $abs ) {
		return ABH_Logs::to_relative( $abs );
	}

	/**
	 * Diagnóstico principal. Devuelve null si el motor no reconoce el caso
	 * (entonces le toca a la IA).
	 *
	 * @param array $incident Incidencia del registro.
	 * @return array|null
	 */
	public static function diagnose( $incident ) {
		$msg = isset( $incident['message'] ) ? (string) $incident['message'] : '';
		if ( '' === $msg ) {
			return null;
		}

		// El panel diagnostica cada incidencia dos veces: una al clasificarla y
		// otra al dibujar su tarjeta. Con cuarenta incidencias eran ochenta
		// pasadas, y algunas tocan disco (leer una cabecera de plugin, buscar
		// un tema). La respuesta solo depende de la incidencia, así que se
		// recuerda dentro de la misma petición.
		static $memo = array();
		$clave = md5( $msg . '|' . ( isset( $incident['rel_path'] ) ? $incident['rel_path'] : '' ) . '|' . ( isset( $incident['kind'] ) ? $incident['kind'] : '' ) . '|' . ( isset( $incident['line'] ) ? $incident['line'] : '' ) );
		if ( array_key_exists( $clave, $memo ) ) {
			return $memo[ $clave ];
		}
		$memo[ $clave ] = self::run_detectors( $incident, $msg );
		if ( count( $memo ) > 200 ) {
			array_shift( $memo );
		}
		return $memo[ $clave ];
	}

	/**
	 * Recorre los detectores en orden y devuelve el primero que reconoce el caso.
	 *
	 * @param array  $incident Incidencia.
	 * @param string $msg      Mensaje.
	 * @return array|null
	 */
	private static function run_detectors( $incident, $msg ) {

		$handlers = array(
			'disk_full',
			'permissions',
			'duplicate_constant',
			'textdomain_early',
			'null_to_core',
			'missing_path',
			'memory',
			'timeout',
			'core_missing',
			'missing_extension',
		);

		foreach ( $handlers as $h ) {
			$found = call_user_func( array( __CLASS__, 'detect_' . $h ), $msg, $incident );
			if ( ! is_array( $found ) ) {
				continue;
			}

			// El diagnóstico se conserva SIEMPRE: nombra al culpable y eso es
			// útil pase lo que pase. Lo que se retira, si la incidencia tumbó
			// la petición, es la etiqueta de «no es tuyo»: un fatal no se
			// archiva, y el texto no puede seguir diciendo que no rompe nada.
			//
			// Silenciar el detector entero —como se intentó primero— devolvía
			// la tarjeta de «comparar y restaurar el núcleo», que es justo la
			// que estos detectores existen para quitar de en medio.
			if ( self::is_fatal_incident( $incident ) && ! empty( $found['benign'] ) ) {
				unset( $found['benign'] );
				$found['diagnosis'] = __( 'ATTENTION: this time the notice ended the request, so it is NOT harmless even if its text looks that way. Your site went down on that page load.', 'ai-bug-hunter' )
					. ' ' . $found['diagnosis'];
			}
			return self::describe( $found );
		}

		return null;
	}

	/**
	 * ¿Es un aviso que NO depende del dueño del sitio?
	 *
	 * Una constante repetida, un plugin ajeno que carga traducciones antes de
	 * tiempo, un valor vacío que llega a una función del núcleo. Ninguno se
	 * repara tocando este sitio, y ninguno debe ocupar sitio en la lista de
	 * pendientes: ahí solo genera la sensación de que la herramienta no sabe
	 * resolverlos.
	 *
	 * Existe como función y no como comprobación suelta porque el criterio lo
	 * necesitan DOS sitios —el panel y el contexto del chat— y ya se ha pagado
	 * varias veces el precio de tener el mismo criterio escrito dos veces: una
	 * copia se actualiza, la otra no, y las dos pantallas se contradicen.
	 *
	 * @param array $incident Incidencia del registro.
	 * @return bool
	 */
	public static function is_benign( $incident ) {
		// Un fatal NUNCA es inofensivo, diga lo que diga su texto.
		//
		// En sitios con un manejador que convierte avisos en excepciones
		// —Whoops, Sentry, cualquier set_error_handler que lance
		// ErrorException— el registro guarda cosas como «PHP Fatal error:
		// Uncaught ErrorException: str_replace(): Passing null to parameter
		// #3». El texto es el de un aviso; la consecuencia es una pantalla en
		// blanco. Sin esta compuerta, ese fatal salía de la lista de
		// pendientes, se archivaba bajo «no son fallos de tu sitio» y se le
		// decía al dueño que el sitio sigue funcionando. Con el sitio caído.
		if ( self::is_fatal_incident( $incident ) ) {
			return false;
		}
		$diag = self::diagnose( $incident );
		return is_array( $diag ) && ! empty( $diag['benign'] );
	}

	/**
	 * ¿La incidencia tumbó la petición?
	 *
	 * @param array $incident Incidencia.
	 * @return bool
	 */
	public static function is_fatal_incident( $incident ) {
		$kind = isset( $incident['kind'] ) ? strtolower( trim( (string) $incident['kind'] ) ) : '';
		if ( '' !== $kind ) {
			foreach ( array( 'fatal', 'parse' ) as $grave ) {
				if ( false !== strpos( $kind, $grave ) ) {
					return true;
				}
			}
		}
		if ( isset( $incident['severity'] ) && (int) $incident['severity'] >= 90 ) {
			return true;
		}
		// Aunque el tipo llegue vacío, «Uncaught» solo aparece en excepciones
		// que nadie atrapó: eso terminó la petición.
		return (bool) preg_match( '/\bUncaught\b/i', isset( $incident['message'] ) ? (string) $incident['message'] : '' );
	}

	/**
	 * Completa un diagnóstico con los textos del catálogo.
	 *
	 * @param array $d Diagnóstico.
	 * @return array
	 */
	public static function describe( $d ) {
		$cat  = self::catalog();
		$code = isset( $d['code'] ) ? $d['code'] : '';
		$info = isset( $cat[ $code ] ) ? $cat[ $code ] : array(
			'titulo'      => $code,
			'explicacion' => '',
		);
		return array_merge(
			array(
				'source'  => self::SIGNATURE,
				'fixable' => false,
				'steps'   => array(),
			),
			$info,
			$d
		);
	}

	/**
	 * Disco lleno.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_disk_full( $msg ) {
		if ( ! preg_match( '/No space left on device/i', $msg ) ) {
			return null;
		}
		return array(
			'code'      => 'ABH-ENV-008',
			'diagnosis' => __( 'The server ran out of disk space. No code fix solves this, and while it lasts uploads, caches and backups can fail.', 'ai-bug-hunter' ),
			'steps'     => array(
				__( 'Go into your hosting panel and check the account\'s disk usage.', 'ai-bug-hunter' ),
				__( 'Delete old backups, caches and old logs: they are usually what fills up the quota.', 'ai-bug-hunter' ),
				__( 'If the disk is at its real limit, ask your provider to increase it.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * La misma constante definida dos veces.
	 *
	 * Estos avisos los provocó esta propia herramienta: el panel indicaba añadir
	 * tres líneas define() a wp-config.php sin comprobar si ya estaban, y quien
	 * las añadía se encontraba con un aviso por petición y una incidencia
	 * bloqueada sin ninguna acción útil. Ahora el consejo comprueba antes (ver
	 * ABH_Logs::debug_config_advice), y el aviso que ya se generó tiene un
	 * diagnóstico exacto: qué línea sobra y por qué es inofensiva.
	 *
	 * Nada de esto escribe en wp-config.php. Se lee para localizar el número de
	 * línea de la primera definición, y solo eso: ni una línea de ese archivo
	 * aparece en el panel, porque ahí viven las credenciales.
	 *
	 * @param string $msg      Mensaje.
	 * @param array  $incident Incidencia.
	 * @return array|null
	 */
	private static function detect_duplicate_constant( $msg, $incident = array() ) {
		if ( ! preg_match( '/Constant\s+([A-Za-z_][A-Za-z0-9_]*)\s+already\s+defined/i', $msg, $m ) ) {
			return null;
		}
		$nombre = $m[1];
		$rel    = isset( $incident['rel_path'] ) ? (string) $incident['rel_path'] : '';
		$linea  = isset( $incident['line'] ) ? (int) $incident['line'] : 0;
		$abs    = isset( $incident['file'] ) ? (string) $incident['file'] : '';
		$nombre_archivo = '' !== $rel ? $rel : __( 'the file the log points to', 'ai-bug-hunter' );

		// Número de línea de la PRIMERA definición, si se puede leer.
		$primera = self::first_definition_line( $abs, $nombre, $linea );

		// El valor en vigor se lee de la memoria de PHP, no del archivo, y solo
		// para un puñado de constantes de depuración cuyo valor no es secreto.
		$vigente = '';
		$publicas = array( 'WP_DEBUG', 'WP_DEBUG_LOG', 'WP_DEBUG_DISPLAY', 'SCRIPT_DEBUG', 'SAVEQUERIES', 'WP_CACHE', 'DISALLOW_FILE_EDIT', 'DISALLOW_FILE_MODS', 'WP_ENVIRONMENT_TYPE' );
		if ( in_array( strtoupper( $nombre ), $publicas, true ) && defined( $nombre ) ) {
			$valor = constant( $nombre );
			if ( is_bool( $valor ) ) {
				$vigente = $valor ? 'true' : 'false';
			} elseif ( is_scalar( $valor ) ) {
				$vigente = (string) $valor;
			}
		}

		$pasos = array();
		if ( $linea > 0 ) {
			$pasos[] = sprintf(
				/* translators: 1: archivo, 2: número de línea, 3: nombre de la constante. */
				__( 'Open %1$s and go to line %2$d: that is where %3$s is defined again.', 'ai-bug-hunter' ),
				$nombre_archivo,
				$linea,
				$nombre
			);
			$pasos[] = $primera > 0
				? sprintf(
					/* translators: 1: línea repetida, 2: primera línea. */
					__( 'Delete line %1$d. The good one is line %2$d, which is the one PHP is actually using; the other does nothing but leave the notice.', 'ai-bug-hunter' ),
					$linea,
					$primera
				)
				: sprintf(
					/* translators: %d: número de línea. */
					__( 'Delete line %d. It is the duplicate: PHP had already taken the value from an earlier definition and ignores this one.', 'ai-bug-hunter' ),
					$linea
				);
		} else {
			$pasos[] = sprintf(
				/* translators: 1: nombre de la constante, 2: archivo. */
				__( 'Look for %1$s in %2$s: it appears twice and one of them is redundant.', 'ai-bug-hunter' ),
				$nombre,
				$nombre_archivo
			);
		}
		if ( '' !== $vigente ) {
			$pasos[] = sprintf(
				/* translators: 1: constante, 2: valor. */
				__( 'If what you wanted was to change the value, edit the first line instead of adding another one: right now %1$s is %2$s.', 'ai-bug-hunter' ),
				$nombre,
				$vigente
			);
		}
		$pasos[] = __( 'Make a copy of the file before touching it. You make this change yourself: this tool never writes to wp-config.php.', 'ai-bug-hunter' );

		return array(
			'code'      => 'ABH-ENV-009',
			'benign'    => true,
			'fixable'   => false,
			'diagnosis' => sprintf(
				/* translators: 1: constante, 2: archivo. */
				__( 'This does not break anything: %1$s is defined twice in %2$s. PHP keeps the first value, discards the second and logs a notice on every request. That is why you see it repeated so many times: it is the same notice, not many errors.', 'ai-bug-hunter' ),
				$nombre,
				$nombre_archivo
			),
			'steps'     => $pasos,
		);
	}

	/**
	 * Acota una ruta absoluta ANTES de leerla y devuelve la canónica.
	 *
	 * Aquí no se escribe nada: se lee para localizar un número de línea. Aun
	 * así, una ruta que no se comprueba es una ruta que alguien elige.
	 *
	 * La resolución NO se reimplementa: la hace ABH_Guard::resolve_existing_path(),
	 * que rechaza '..', comprueba is_link() en CADA segmento y fija el resultado
	 * con realpath contra ABSPATH.
	 *
	 * Sobre las raíces: ABH_Engine::writable_roots() es la frontera de ESCRITURA
	 * y vive clavada dentro de wp-content. wp-config.php —el caso para el que
	 * existe este lector— está en la raíz de WordPress y además figura en
	 * ABH_Limits::never(), así que exigirle esas raíces dejaría el detector mudo
	 * justo en su único caso real, que es peor que no arreglar nada. Se exigen
	 * las raíces de escritura a todo lo que cuelgue de una carpeta, y a un
	 * archivo SUELTO de la raíz se le exige solo la contención en ABSPATH:
	 * exactamente la política de LECTURA que ABH_Logs::safe_location() ya
	 * aplica para poder señalar wp-config.php. Esto no amplía nada de lo que
	 * pueda escribirse.
	 *
	 * @param string $abs Ruta absoluta candidata.
	 * @return string Ruta canónica acotada, o cadena vacía.
	 */
	private static function contained_read_path( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || ! class_exists( 'ABH_Guard' ) || ! class_exists( 'ABH_Engine' ) ) {
			return '';
		}

		$rel = class_exists( 'ABH_Logs' ) ? ABH_Logs::to_relative( $abs ) : '';
		if ( '' === $rel ) {
			// Hay instalaciones cuya raíz se sirve por enlace simbólico: ABSPATH
			// es el enlace y la ruta que llega es la real. Se reintenta contra la
			// raíz canónica antes de descartar, igual que hace el localizador.
			$raiz = realpath( ABSPATH );
			if ( false !== $raiz ) {
				$raiz = rtrim( wp_normalize_path( $raiz ), '/' );
				if ( ABH_Guard::absolute_in_root( $abs, $raiz ) ) {
					$rel = ltrim( substr( $abs, strlen( $raiz ) ), '/' );
				}
			}
		}

		$rel = ABH_Guard::normalize( $rel );
		if ( '' === $rel || '..' === $rel ) {
			return '';
		}

		$raices = ( false === strpos( $rel, '/' ) ) ? null : ABH_Engine::writable_roots();
		$real   = ABH_Guard::resolve_existing_path( $rel, $raices );
		if ( false === $real || ! is_file( $real ) || is_link( $real ) ) {
			return '';
		}
		return (string) $real;
	}

	/**
	 * Línea donde una constante se define por primera vez.
	 *
	 * Devuelve un número de línea, nunca contenido. El archivo puede ser
	 * wp-config.php y ahí están las credenciales del sitio.
	 *
	 * @param string $abs       Ruta absoluta del archivo.
	 * @param string $constante Nombre de la constante.
	 * @param int    $antes_de  Línea repetida que informó PHP.
	 * @return int 0 si no se pudo determinar.
	 */
	private static function first_definition_line( $abs, $constante, $antes_de ) {
		// Contención ANTES de abrir. Ver contained_read_path(): hasta aquí solo
		// llegaban `is_readable` y `is_link`, que no dicen nada de dónde está el
		// archivo. El localizador del registro ya no manda rutas sin acotar,
		// pero la contención tiene que vivir donde se abre, no en el llamador.
		$abs = self::contained_read_path( $abs );
		if ( '' === $abs || ! @is_readable( $abs ) || is_link( $abs ) ) {
			return 0;
		}
		$tam = @filesize( $abs );
		if ( false === $tam || $tam > 1048576 ) {
			return 0;
		}
		$fh = @fopen( $abs, 'rb' );
		if ( ! $fh ) {
			return 0;
		}
		$re = '/^\s*(?:define\s*\(\s*[\'"]' . preg_quote( $constante, '/' ) . '[\'"]|const\s+' . preg_quote( $constante, '/' ) . '\s*=)/i';
		$n  = 0;
		$encontrada = 0;
		while ( false !== ( $linea = fgets( $fh ) ) ) {
			$n++;
			if ( $antes_de > 0 && $n >= $antes_de ) {
				break;
			}
			if ( preg_match( $re, $linea ) ) {
				$encontrada = $n;
				break;
			}
		}
		fclose( $fh );
		return $encontrada;
	}

	/**
	 * Un plugin o tema pide sus traducciones antes de tiempo.
	 *
	 * El culpable viene ESCRITO en el mensaje: WordPress nombra el dominio de
	 * traducción, y el dominio identifica al plugin. Aun así, esta incidencia se
	 * presentaba como «archivo del núcleo protegido» con dos botones inútiles —
	 * comparar y restaurar un archivo que el propio panel acababa de verificar
	 * idéntico— y con una frase que prometía un botón «¿Dónde está la causa?»
	 * que no se dibujaba para esta familia de errores.
	 *
	 * Ese era el defecto: teníamos la respuesta delante y ofrecíamos otra cosa.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_textdomain_early( $msg, $incident = array() ) {
		// El ancla es el nombre de la función, que WordPress NO traduce. La
		// frase que lo acompaña sí se traduce: en un WordPress en español el
		// registro dice «La carga de traducciones para el dominio …». Exigir el
		// texto en inglés dejaba el detector muerto justo en los sitios de este
		// plugin, que es de habla hispana.
		if ( false === stripos( $msg, '_load_textdomain_just_in_time' ) ) {
			return null;
		}

		// El dominio viaja entre <code></code> en cualquier idioma. Si no está,
		// se buscan candidatos alrededor de la palabra «domain»/«dominio» —en
		// inglés va delante, en español detrás— y gana el que corresponda a algo
		// realmente instalado.
		//
		// Una regla de proximidad a secas capturaba «was» en el mensaje inglés
		// («the woocommerce domain was triggered»), y entonces se acusaba a un
		// plugin llamado «was». Nombrar al culpable equivocado es peor que no
		// nombrar a ninguno.
		$dominio    = '';
		$candidatos = array();
		if ( preg_match( '#(?:<code>|&lt;code&gt;)\s*([A-Za-z0-9_.\-]+)\s*(?:</code>|&lt;/code&gt;)#i', $msg, $m ) ) {
			$candidatos[] = $m[1];
		} else {
			if ( preg_match( '#([A-Za-z0-9_.\-]{2,})\s+\b(?:domain|dominio)\b#i', $msg, $m ) ) {
				$candidatos[] = $m[1];
			}
			if ( preg_match( '#\b(?:domain|dominio)\b[^A-Za-z0-9_.\-]{0,4}([A-Za-z0-9_.\-]{2,})#i', $msg, $m ) ) {
				$candidatos[] = $m[1];
			}
		}

		// Palabras de la propia frase que nunca son un dominio.
		$ruido = array( 'was', 'the', 'for', 'is', 'el', 'la', 'of', 'se', 'ha', 'una', 'del', 'que', 'loading', 'translation', 'traducciones', 'carga' );
		foreach ( $candidatos as $i => $c ) {
			$c = trim( $c, ".,;:'\"" );
			if ( '' === $c || in_array( strtolower( $c ), $ruido, true ) ) {
				unset( $candidatos[ $i ] );
				continue;
			}
			$candidatos[ $i ] = $c;
		}
		$candidatos = array_values( $candidatos );

		// Gana el que exista de verdad en el sitio.
		foreach ( $candidatos as $c ) {
			$prueba = self::owner_of_textdomain( $c );
			if ( '' !== $prueba['nombre'] ) {
				$dominio = $c;
				break;
			}
		}
		if ( '' === $dominio && ! empty( $candidatos ) ) {
			$dominio = $candidatos[0];
		}

		if ( '' === $dominio ) {
			return null;
		}
		$quien   = self::owner_of_textdomain( $dominio );

		$culpable = '' !== $quien['nombre']
			? sprintf(
				/* translators: 1: nombre del plugin o tema, 2: tipo. */
				__( '%1$s (%2$s)', 'ai-bug-hunter' ),
				$quien['nombre'],
				'theme' === $quien['tipo'] ? __( 'theme', 'ai-bug-hunter' ) : __( 'plugin', 'ai-bug-hunter' )
			)
			: sprintf(
				/* translators: %s: dominio de traducción. */
				__( 'the one that uses the “%s” domain', 'ai-bug-hunter' ),
				$dominio
			);

		$pasos = array(
			sprintf(
				/* translators: %s: nombre del plugin o tema. */
				__( 'This has to be fixed by the author of %s, not by you: it is their code that asks for the translations too early.', 'ai-bug-hunter' ),
				$culpable
			),
			__( 'Check whether there is a pending update for that plugin or theme. It is a known notice since WordPress 6.7 and most authors have already fixed it.', 'ai-bug-hunter' ),
			__( 'If there is no update, let the author know. In the meantime it does not break anything: it just fills the log.', 'ai-bug-hunter' ),
			__( 'What you should NOT do is touch the core file shown above. That file is intact and is only where the notice is printed.', 'ai-bug-hunter' ),
		);

		return array(
			'code'      => 'ABH-ENV-010',
			'benign'    => true,
			'fixable'   => false,
			'culpable'  => $quien['ruta'],
			'diagnosis' => sprintf(
				/* translators: 1: culpable, 2: dominio. */
				__( 'The culprit is %1$s. It asks for its translations («%2$s») before the moment WordPress has them ready, and WordPress logs it. The core file you see above has nothing wrong with it: it is only where the notice is printed.', 'ai-bug-hunter' ),
				$culpable,
				$dominio
			),
			'steps'     => $pasos,
		);
	}

	/**
	 * A qué plugin o tema instalado pertenece un dominio de traducción.
	 *
	 * @param string $dominio Dominio.
	 * @return array nombre, tipo, ruta
	 */
	private static function owner_of_textdomain( $dominio ) {
		$vacio = array( 'nombre' => '', 'tipo' => '', 'ruta' => '' );
		if ( ! preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', (string) $dominio ) ) {
			return $vacio;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			$helper = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_readable( $helper ) ) {
				require_once $helper;
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $archivo => $datos ) {
				$carpeta = strtok( $archivo, '/' );
				$suyo    = isset( $datos['TextDomain'] ) ? (string) $datos['TextDomain'] : '';
				if ( $dominio === $suyo || $dominio === $carpeta ) {
					return array(
						'nombre' => ! empty( $datos['Name'] ) ? (string) $datos['Name'] : $carpeta,
						'tipo'   => 'plugin',
						'ruta'   => 'wp-content/plugins/' . $carpeta,
					);
				}
			}
		}

		if ( function_exists( 'wp_get_theme' ) ) {
			$tema = wp_get_theme( $dominio );
			if ( $tema && $tema->exists() ) {
				return array(
					'nombre' => (string) $tema->get( 'Name' ),
					'tipo'   => 'theme',
					'ruta'   => 'wp-content/themes/' . $dominio,
				);
			}
		}

		return $vacio;
	}

	/**
	 * Un valor vacío llega a una función del núcleo.
	 *
	 * PHP 8.1 avisa de esto en el archivo donde está la función, que casi
	 * siempre es del núcleo. Repararlo ahí sería parchear al mensajero: el
	 * archivo del núcleo es correcto y en la siguiente actualización se
	 * sobrescribe. El culpable es quien pasó el valor vacío.
	 *
	 * @param string $msg      Mensaje.
	 * @param array  $incident Incidencia.
	 * @return array|null
	 */
	private static function detect_null_to_core( $msg, $incident = array() ) {
		if ( ! preg_match( '/([A-Za-z_][A-Za-z0-9_]*)\(\):\s*Passing null to parameter #(\d+)\s*\(\$([A-Za-z0-9_]+)\)/i', $msg, $m ) ) {
			return null;
		}
		$rel = isset( $incident['rel_path'] ) ? (string) $incident['rel_path'] : '';
		// Solo se hace cargo cuando el aviso salta DENTRO del núcleo. Si salta
		// en un plugin, el arreglo está en ese mismo archivo y el flujo normal
		// —con su parche y su diff— es el correcto.
		$en_nucleo = ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) );
		if ( ! $en_nucleo ) {
			return null;
		}

		$funcion   = $m[1];
		$parametro = $m[3];

		return array(
			'code'      => 'ABH-ENV-011',
			'benign'    => true,
			'fixable'   => false,
			'diagnosis' => sprintf(
				/* translators: 1: función, 2: parámetro, 3: ruta del archivo del núcleo. */
				__( 'Something called %1$s() with an empty $%2$s. PHP points at %3$s because that is where the line making the call is, not because that file is wrong: it is a core file and it is correct. What has to change is whatever passed it that empty value. This is a PHP 8.1 notice, not an error: the site keeps working.', 'ai-bug-hunter' ),
				$funcion,
				$parametro,
				'' !== $rel ? $rel : __( 'a core file', 'ai-bug-hunter' )
			),
			'steps'     => array(
				__( 'Do not touch the core file. A patch there disappears with the next WordPress update and does not fix the cause.', 'ai-bug-hunter' ),
				__( 'To find out who is calling it: deactivate half of your plugins, reload the page that triggers the warning and see whether it is still there. Repeating with the half that fails locates the culprit in a few tries.', 'ai-bug-hunter' ),
				__( 'Once you have it, it is its author who has to fix it. Check first whether there is a pending update.', 'ai-bug-hunter' ),
				__( 'If seeing it bothers you, you can hide this issue: it will come back on its own if the notice changes or gets worse.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Permisos insuficientes.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_permissions( $msg ) {
		if ( ! preg_match( '/Permission denied|not writable|failed to open stream:\s*Permission/i', $msg ) ) {
			return null;
		}

		$path = self::extract_path( $msg );
		$info = self::inspect( $path );

		// Si la ruta no existe, el problema real es otro.
		if ( '' !== $path && ! $info['exists'] && ! $info['parent_exists'] ) {
			return null;
		}

		$php_user = self::php_user();

		if ( $info['exists'] ) {
			$es_dir = $info['is_dir'];
			$code   = $es_dir ? 'ABH-ENV-002' : 'ABH-ENV-001';

			// ¿Ya están bien los permisos? Entonces el aviso es historia vieja
			// del registro y no hay nada que corregir.
			$modo_actual = @fileperms( $path );
			$modo_actual = ( false !== $modo_actual ) ? ( $modo_actual & 0777 ) : 0;
			if ( $info['readable'] && $info['writable'] && 0600 === ( $modo_actual & 0600 ) ) {
				return array(
					'code'        => $code,
					'diagnosis'   => sprintf(
						/* translators: 1: ruta, 2: permisos actuales. */
						__( 'This notice was logged when «%1$s» was not accessible, but it now has %2$s permissions and PHP can use it normally. There is nothing to fix: these are old lines in the log.', 'ai-bug-hunter' ),
						$path,
						substr( sprintf( '%o', $modo_actual ), -3 )
					),
					'steps'       => array(
						__( 'If the notice does not appear again with a new date, it is already resolved. You can hide this issue.', 'ai-bug-hunter' ),
					),
					'fixable'     => false,
					'already_ok'  => true,
					'target_path' => $path,
					'inspection'  => $info,
				);
			}

			$diagnosis = sprintf(
				/* translators: 1: tipo, 2: ruta, 3: permisos, 4: dueño, 5: usuario de PHP. */
				__( '%1$s “%2$s” has permissions %3$s and belongs to “%4$s”. PHP runs as “%5$s”, and with those permissions it cannot get access. This is not a code failure: the code is asking for something the system denies it.', 'ai-bug-hunter' ),
				$es_dir ? __( 'The folder', 'ai-bug-hunter' ) : __( 'The file', 'ai-bug-hunter' ),
				$path,
				'' !== $info['perms'] ? $info['perms'] : __( 'unknown', 'ai-bug-hunter' ),
				'' !== $info['owner'] ? $info['owner'] : __( 'unknown', 'ai-bug-hunter' ),
				$php_user
			);

			$target = $es_dir ? self::MODE_DIR : ( self::is_sensitive_log( $path ) ? self::MODE_PRIVATE_FILE : self::MODE_FILE );
			$target_str = substr( sprintf( '%o', $target ), -3 );

			// El registro declarado es el caso en el que más duele mandar a
			// alguien a cPanel, y es justo el que PHP puede resolver solo.
			$fixable = self::env_fixable( $path );

			$steps = array();
			if ( $fixable ) {
				$steps[] = sprintf(
					/* translators: %s: permisos destino. */
					__( 'We can fix it from here: the file belongs to the same user PHP runs as, so setting its permissions to %s is enough.', 'ai-bug-hunter' ),
					$target_str
				);
			} else {
				$steps[] = sprintf(
					/* translators: 1: ruta, 2: permisos destino. */
					__( 'From your file manager or over FTP, change the permissions of «%1$s» to %2$s.', 'ai-bug-hunter' ),
					$path,
					$target_str
				);
				if ( ! $info['we_own_it'] && '' !== $info['owner'] ) {
					$steps[] = sprintf(
						/* translators: 1: dueño del archivo, 2: usuario de PHP. */
						__( 'The file belongs to «%1$s» but PHP runs as «%2$s». If it still fails after changing the permissions, ask your host to adjust the file\'s owner.', 'ai-bug-hunter' ),
						$info['owner'],
						$php_user
					);
				}
			}
			if ( self::is_sensitive_log( $path ) ) {
				$steps[] = __( 'Important: making the log readable allows it to be diagnosed, but does not guarantee that it is protected over HTTP. THOTH Security must check again that it is not downloadable.', 'ai-bug-hunter' );
				$steps[] = __( 'The definitive solution in production is to turn off debug or move the log outside the webroot. AI Bug Hunter does not modify wp-config.php automatically.', 'ai-bug-hunter' );
			} else {
				$steps[] = __( 'Reload this page: if the notice does not come back with a new date, it has been resolved.', 'ai-bug-hunter' );
			}

			return array(
				'code'        => $code,
				'diagnosis'   => $diagnosis,
				'steps'       => $steps,
				'fixable'     => $fixable,
				'fix'         => array(
					'type' => 'chmod',
					'path' => $path,
					'mode' => $target,
				),
				'target_path' => $path,
				'inspection'  => $info,
			);
		}

		// Existe la carpeta pero no el archivo: problema de escritura en la carpeta.
		return array(
			'code'      => 'ABH-ENV-002',
			'diagnosis' => sprintf(
				/* translators: 1: carpeta, 2: usuario de PHP. */
				__( 'PHP cannot write inside «%1$s» (it runs as «%2$s»). That is why it cannot create the file it needs.', 'ai-bug-hunter' ),
				$info['parent'],
				$php_user
			),
			'steps'     => array(
				sprintf(
					/* translators: %s: carpeta. */
					__( 'Change the permissions of the folder «%s» to 755 from your file manager or over FTP.', 'ai-bug-hunter' ),
					$info['parent']
				),
				__( 'If your host uses a different user for PHP, ask them to adjust the owner of that folder.', 'ai-bug-hunter' ),
			),
			'target_path' => $info['parent'],
			'inspection'  => $info,
		);
	}

	/**
	 * Archivo o carpeta inexistente.
	 *
	 * @param string $msg Mensaje.
	 * @param array  $incident Incidencia.
	 * @return array|null
	 */
	private static function detect_missing_path( $msg, $incident = array() ) {
		if ( ! preg_match( '/No such file or directory|stat failed for|Failed opening/i', $msg ) ) {
			return null;
		}

		$path = self::extract_path( $msg );
		if ( '' === $path ) {
			return null;
		}

		$info = self::inspect( $path );
		if ( $info['exists'] ) {
			// Existe: entonces era un problema de permisos, no de ausencia.
			return null;
		}

		$rel   = self::rel_of( $path );
		$steps = array();

		$origen = '';
		if ( preg_match( '#wp-content/plugins/([^/]+)/#', wp_normalize_path( $rel ), $m ) ) {
			$origen  = $m[1];
			$steps[] = sprintf(
				/* translators: %s: carpeta del plugin. */
				__( 'The path belongs to the plugin «%s». Most likely its installation was left incomplete: reinstall it from Plugins.', 'ai-bug-hunter' ),
				$origen
			);
		} elseif ( preg_match( '#wp-content/themes/([^/]+)/#', wp_normalize_path( $rel ), $m ) ) {
			$origen  = $m[1];
			$steps[] = sprintf(
				/* translators: %s: carpeta del tema. */
				__( 'The path belongs to the theme «%s». Reinstall it from Appearance › Themes.', 'ai-bug-hunter' ),
				$origen
			);
		} else {
			$steps[] = __( 'Check whether the file was deleted by accident or whether a backup only restored it halfway.', 'ai-bug-hunter' );
		}

		if ( $info['parent_exists'] ) {
			$steps[] = __( 'The folder that contains it does exist, so only that file is missing.', 'ai-bug-hunter' );
		} else {
			$steps[] = sprintf(
				/* translators: %s: carpeta. */
				__( 'The «%s» folder does not exist either, so the whole block is missing.', 'ai-bug-hunter' ),
				$info['parent']
			);
		}

		return array(
			'code'        => 'ABH-ENV-003',
			'diagnosis'   => sprintf(
				/* translators: %s: ruta. */
				__( 'The path «%s» does not exist on disk. The code looks for it and it is not there: there is nothing to fix in the code, the file is missing.', 'ai-bug-hunter' ),
				$path
			),
			'steps'       => $steps,
			'target_path' => $path,
			'inspection'  => $info,
		);
	}

	/**
	 * Memoria agotada.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_memory( $msg ) {
		if ( ! preg_match( '/Allowed memory size of (\d+) bytes exhausted/i', $msg, $m ) ) {
			return null;
		}
		$limite = self::human_bytes( $m[1] );
		$pedido = '';
		if ( preg_match( '/tried to allocate (\d+) bytes/i', $msg, $m2 ) ) {
			$pedido = self::human_bytes( $m2[1] );
		}

		$ini_limit = @ini_get( 'memory_limit' );
		$wp_limit  = defined( 'WP_MEMORY_LIMIT' ) ? WP_MEMORY_LIMIT : __( 'not defined', 'ai-bug-hunter' );

		$diagnosis = sprintf(
			/* translators: 1: límite alcanzado, 2: memory_limit de PHP, 3: WP_MEMORY_LIMIT. */
			__( 'The process used up the %1$s of memory allowed. PHP has memory_limit at %2$s and WordPress has WP_MEMORY_LIMIT at %3$s. This is not fixed by touching the code: it needs more memory, or you need to find what is consuming it.', 'ai-bug-hunter' ),
			$limite,
			$ini_limit ? $ini_limit : __( 'unknown', 'ai-bug-hunter' ),
			$wp_limit
		);
		if ( '' !== $pedido ) {
			$diagnosis .= ' ' . sprintf(
				/* translators: %s: memoria solicitada. */
				__( 'The operation that failed was asking for %s at once.', 'ai-bug-hunter' ),
				$pedido
			);
		}

		return array(
			'code'      => 'ABH-ENV-004',
			'diagnosis' => $diagnosis,
			'steps'     => array(
				__( 'Raise the limit by adding this to wp-config.php, before «That\'s all, stop editing»: define( \'WP_MEMORY_LIMIT\', \'512M\' );', 'ai-bug-hunter' ),
				__( 'You make this change yourself: the plugin never writes to wp-config.php.', 'ai-bug-hunter' ),
				__( 'If it still runs out after raising it, the usage is abnormal: deactivate plugins one by one to see which one triggers it.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Tiempo de ejecución agotado.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_timeout( $msg ) {
		if ( ! preg_match( '/Maximum execution time of (\d+) seconds? exceeded/i', $msg, $m ) ) {
			return null;
		}
		return array(
			'code'      => 'ABH-ENV-005',
			'diagnosis' => sprintf(
				/* translators: 1: segundos permitidos, 2: valor actual de max_execution_time. */
				__( 'The server cut off the process after it went past %1$d seconds (current max_execution_time: %2$s). It is almost always a heavy task, a slow query or an external call that does not answer, not a syntax error.', 'ai-bug-hunter' ),
				(int) $m[1],
				(string) @ini_get( 'max_execution_time' )
			),
			'steps'     => array(
				__( 'Identify which process triggers it: imports, backups and syncs are the usual suspects.', 'ai-bug-hunter' ),
				__( 'If it is a legitimate task that takes a while, ask your host to raise max_execution_time for that process.', 'ai-bug-hunter' ),
				__( 'If it repeats on every visit, something is blocked: check calls to external servers that do not respond.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Núcleo de WordPress incompleto.
	 *
	 * @param string $msg      Mensaje.
	 * @param array  $incident Incidencia.
	 * @return array|null
	 */
	private static function detect_core_missing( $msg, $incident = array() ) {
		if ( ! preg_match( '/Class\s+["\']?(WP_[A-Za-z0-9_]+)["\']?\s+not found/i', $msg, $m ) ) {
			return null;
		}

		$clase = $m[1];
		$rel   = isset( $incident['rel_path'] ) ? $incident['rel_path'] : '';

		// Solo lo tratamos como núcleo dañado si el error ocurre dentro del núcleo
		// o si el archivo de esa clase falta realmente.
		$en_nucleo = ( 0 === strpos( $rel, 'wp-includes/' ) || 0 === strpos( $rel, 'wp-admin/' ) );

		$slug     = 'class-' . strtolower( str_replace( '_', '-', $clase ) ) . '.php';
		$hallados = @glob( ABSPATH . 'wp-includes/' . $slug );
		if ( empty( $hallados ) ) {
			$hallados = @glob( ABSPATH . 'wp-includes/*/' . $slug );
		}
		$falta_archivo = empty( $hallados );

		if ( ! $en_nucleo && ! $falta_archivo ) {
			return null;
		}

		$diagnosis = sprintf(
			/* translators: %s: nombre de la clase. */
			__( 'WordPress is looking for its own class “%s” and cannot find it.', 'ai-bug-hunter' ),
			$clase
		);
		if ( $falta_archivo ) {
			$diagnosis .= ' ' . sprintf(
				/* translators: %s: nombre del archivo esperado. */
				__( 'The file that should define it (%s) is not in wp-includes. Your core installation is incomplete, usually because of an interrupted update or a half-finished FTP upload.', 'ai-bug-hunter' ),
				$slug
			);
		} else {
			$diagnosis .= ' ' . __( 'The file exists, so something is preventing it from loading: it may be one core version mixed with another.', 'ai-bug-hunter' );
		}
		$diagnosis .= ' ' . __( 'Patching code here fixes nothing and would be lost in the next update.', 'ai-bug-hunter' );

		return array(
			'code'      => 'ABH-ENV-006',
			'diagnosis' => $diagnosis,
			'steps'     => array(
				__( 'Go to Dashboard › Updates and click «Reinstall now». It replaces the core files without touching your content, your plugins or your theme.', 'ai-bug-hunter' ),
				__( 'If the button does not appear, download WordPress from wordpress.org and upload only the wp-includes and wp-admin folders by FTP, overwriting.', 'ai-bug-hunter' ),
				__( 'Never overwrite wp-config.php or the wp-content folder while doing so.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Extensión de PHP ausente.
	 *
	 * @param string $msg Mensaje.
	 * @return array|null
	 */
	private static function detect_missing_extension( $msg ) {
		if ( ! preg_match( '/Call to undefined function\s+([a-z0-9_\\\\]+)\s*\(/i', $msg, $m ) ) {
			return null;
		}

		$func = strtolower( ltrim( $m[1], '\\' ) );
		$mapa = array(
			'curl_'      => 'curl',
			'mysqli_'    => 'mysqli',
			'mb_'        => 'mbstring',
			'imagecreate' => 'gd',
			'imagejpeg'  => 'gd',
			'imagepng'   => 'gd',
			'imagewebp'  => 'gd',
			'gd_info'    => 'gd',
			'openssl_'   => 'openssl',
			'json_'      => 'json',
			'simplexml_' => 'simplexml',
			'iconv'      => 'iconv',
			'bc'         => 'bcmath',
			'gmp_'       => 'gmp',
			'exif_'      => 'exif',
			'ftp_'       => 'ftp',
			'ldap_'      => 'ldap',
			'soap'       => 'soap',
			'zip_'       => 'zip',
			'zlib_'      => 'zlib',
			'gz'         => 'zlib',
			'intl'       => 'intl',
			'sodium_'    => 'sodium',
			'xml_'       => 'xml',
			'imap_'      => 'imap',
			'pcntl_'     => 'pcntl',
			'posix_'     => 'posix',
		);

		$ext = '';
		foreach ( $mapa as $prefijo => $nombre ) {
			if ( 0 === strpos( $func, $prefijo ) ) {
				$ext = $nombre;
				break;
			}
		}

		// Sin extensión reconocida es un problema de código: que lo vea la IA.
		if ( '' === $ext ) {
			return null;
		}
		// Si la extensión SÍ está cargada, el fallo es de código.
		if ( function_exists( 'extension_loaded' ) && @extension_loaded( $ext ) ) {
			return null;
		}

		return array(
			'code'      => 'ABH-ENV-007',
			'diagnosis' => sprintf(
				/* translators: 1: función, 2: extensión de PHP. */
				__( 'The code calls %1$s(), which belongs to the PHP extension «%2$s», and that extension is not enabled on your server. No code is missing: the extension is.', 'ai-bug-hunter' ),
				$func,
				$ext
			),
			'steps'     => array(
				sprintf(
					/* translators: %s: extensión. */
					__( 'Ask your host to enable the «%s» extension for your version of PHP.', 'ai-bug-hunter' ),
					$ext
				),
				__( 'On many panels (cPanel, Plesk) you can enable it yourself under «Select PHP version» › Extensions.', 'ai-bug-hunter' ),
				__( 'While it is not active, the plugin or theme that needs it will keep failing.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * ¿El archivo ya tiene el guardián que impide abrirlo directamente?
	 *
	 * @param string $codigo Contenido del archivo.
	 * @return bool
	 */
	public static function has_abspath_guard( $codigo ) {
		return (bool) preg_match( '/\bdefined\s*\(\s*[\'"]ABSPATH[\'"]\s*\)/', $codigo );
	}

	/**
	 * ¿Se le puede añadir el guardián de forma segura y automática?
	 *
	 * Se exige que el archivo empiece por la etiqueta de apertura de PHP. Si
	 * empieza con HTML o con otra cosa, es una plantilla y ahí no entramos.
	 *
	 * @param string $codigo Contenido del archivo.
	 * @return bool
	 */
	public static function can_add_guard( $codigo ) {
		if ( '' === trim( $codigo ) ) {
			return false;
		}
		if ( self::has_abspath_guard( $codigo ) ) {
			return false;
		}
		// El BOM entero es opcional, no solo su último byte.
		return (bool) preg_match( '/^(?:\xEF\xBB\xBF)?\s*<\?php\b/', $codigo );
	}

	/**
	 * Inserta el guardián justo antes de la primera instrucción real,
	 * respetando la etiqueta de apertura y el bloque de comentarios inicial.
	 *
	 * @param string $codigo Contenido original.
	 * @return string|false Contenido con el guardián, o false si no procede.
	 */
	public static function add_abspath_guard( $codigo ) {
		if ( ! self::can_add_guard( $codigo ) ) {
			return false;
		}
		if ( ! function_exists( 'token_get_all' ) ) {
			return false;
		}

		$tokens = @token_get_all( $codigo );
		if ( ! is_array( $tokens ) || empty( $tokens ) ) {
			return false;
		}

		// Se avanza hasta la primera instrucción que no sea apertura, espacio,
		// comentario ni declare(): ahí va el guardián.
		$pos     = 0;
		$saltar  = array( T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT );
		$offset  = 0;
		$colocar = null;

		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				$texto = $token[1];
				$id    = $token[0];
			} else {
				$texto = $token;
				$id    = null;
			}

			if ( null !== $id && in_array( $id, $saltar, true ) ) {
				$offset += strlen( $texto );
				++$pos;
				continue;
			}

			// declare(strict_types=1); tiene que seguir siendo lo primero.
			if ( null !== $id && defined( 'T_DECLARE' ) && T_DECLARE === $id ) {
				$fin = strpos( $codigo, ';', $offset );
				if ( false === $fin ) {
					return false;
				}
				$colocar = $fin + 1;
				break;
			}

			$colocar = $offset;
			break;
		}

		if ( null === $colocar ) {
			// Archivo sin instrucciones: se coloca al final.
			$colocar = strlen( $codigo );
		}

		$guardia = "\n\nif ( ! defined( 'ABSPATH' ) ) {\n\texit; // Salida si se accede directamente.\n}\n";

		$antes   = rtrim( substr( $codigo, 0, $colocar ), "\n\r" );
		$despues = ltrim( substr( $codigo, $colocar ), "\n\r" );

		return $antes . $guardia . "\n" . $despues;
	}


	/**
	 * Los registros pueden contener rutas, correos, tokens y consultas.
	 * Si el archivo pertenece a PHP, 0600 basta para que el proceso lo use y
	 * evita convertirlo deliberadamente en un archivo público 0644.
	 *
	 * @param string $path Ruta.
	 * @return bool
	 */
	public static function is_sensitive_log( $path ) {
		$base = strtolower( basename( (string) $path ) );
		$ext  = strtolower( pathinfo( $base, PATHINFO_EXTENSION ) );
		return 'log' === $ext || false !== strpos( $base, 'debug' ) || false !== strpos( $base, 'error_log' );
	}

	/**
	 * Rutas que el motor nunca toca ni siquiera para permisos.
	 *
	 * @param string $abs Ruta absoluta.
	 * @return bool
	 */
	/**
	 * ¿Puede HUNTER corregir por sí mismo los permisos de esta ruta?
	 *
	 * Única fuente de verdad del criterio. Existía copiado en cuatro sitios —
	 * el diagnóstico, la vista previa, la aplicación y el panel— y al ampliarlo
	 * para el registro declarado se actualizaron tres. El cuarto seguía diciendo
	 * que no, así que el botón aparecía y al pulsarlo se detenía.
	 *
	 * @param string $abs Ruta absoluta.
	 * @return bool
	 */
	public static function env_fixable( $abs ) {
		if ( class_exists( 'ABH_Limits' ) && ABH_Limits::is_never( $abs ) ) {
			return false;
		}
		$info = self::inspect( $abs );
		if ( empty( $info['we_own_it'] ) ) {
			return false;
		}
		return ! self::is_off_limits( $abs ) || self::log_chmod_allowed( $abs );
	}

	/**
	 * ¿Podemos ajustar los permisos del registro de errores declarado?
	 *
	 * El registro suele vivir en la raíz de WordPress, fuera de wp-content, así
	 * que is_off_limits() lo rechaza — con razón para escribir contenido. Pero
	 * aquí no se escribe nada: solo se cambia el modo de un archivo que ya es
	 * nuestro, para poder leerlo. Mandar a alguien a cPanel a hacer un chmod que
	 * PHP puede hacer solo es fallarle.
	 *
	 * Permiso deliberadamente estrecho. Todas las condiciones son obligatorias:
	 *  - La ruta debe ser EXACTAMENTE la que el propio PHP o WordPress declaró
	 *    como registro. No se acepta una ruta traída de fuera.
	 *  - PHP debe ser el dueño: si no lo es, el chmod fallaría igualmente.
	 *  - Archivo regular. Ni enlace simbólico, ni carpeta.
	 *  - Nunca wp-config.php ni .htaccess, pase lo que pase.
	 *  - Dentro de ABSPATH o de su carpeta padre. Nada más lejos.
	 *
	 * @param string $abs Ruta absoluta.
	 * @return bool
	 */
	public static function log_chmod_allowed( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || is_link( $abs ) || ! is_file( $abs ) ) {
			return false;
		}
		// La lista de intocables se consulta en su único sitio.
		if ( class_exists( 'ABH_Limits' ) && ABH_Limits::is_never( $abs ) ) {
			return false;
		}
		if ( ! self::is_sensitive_log( $abs ) ) {
			return false;
		}

		// La ruta tiene que ser una de las que el propio WordPress o PHP
		// declaran como registro. Nunca una traída de fuera.
		if ( ! class_exists( 'ABH_Logs' ) ) {
			return false;
		}
		$real = realpath( $abs );
		if ( false === $real ) {
			return false;
		}
		$real       = wp_normalize_path( $real );
		$reconocida = false;
		foreach ( ABH_Logs::candidate_paths() as $cand ) {
			$rc = realpath( $cand );
			if ( false !== $rc && wp_normalize_path( $rc ) === $real ) {
				$reconocida = true;
				break;
			}
		}
		if ( ! $reconocida ) {
			return false;
		}

		// Acotado a la instalación y a su carpeta padre, nunca más allá.
		$raiz = realpath( ABSPATH );
		if ( false === $raiz ) {
			return false;
		}
		$raiz  = rtrim( wp_normalize_path( $raiz ), '/' );
		$padre = dirname( $raiz );
		if ( 0 !== strpos( $real, $raiz . '/' ) && 0 !== strpos( $real, $padre . '/' ) ) {
			return false;
		}

		$info = self::inspect( $abs );
		return ! empty( $info['we_own_it'] );
	}

	public static function is_off_limits( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || is_link( $abs ) ) {
			return true;
		}
		$real = realpath( $abs );
		$root = realpath( ABSPATH );
		if ( false === $real || false === $root ) {
			return true;
		}
		$real = wp_normalize_path( $real );
		$root = rtrim( wp_normalize_path( $root ), '/' );
		if ( ! ABH_Guard::absolute_in_root( $real, $root ) ) {
			return true;
		}
		$rel = ltrim( substr( $real, strlen( $root ) ), '/' );
		$check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $check['allowed'] ) ) {
			return true;
		}
		return false === ABH_Guard::resolve_existing_path( $rel, ABH_Engine::writable_roots() );
	}

	/**
	 * Reparación determinista de una llamada a función inexistente (typo).
	 *
	 * No usa IA ni consume tokens: la conclusión se apoya solo en hechos
	 * comprobables por la máquina.
	 *   1) El símbolo invocado NO existe en el runtime (PHP + WordPress + todo
	 *      lo que hayan cargado plugins y tema).
	 *   2) En el MISMO archivo se llama a otro símbolo que SÍ existe y cuyo
	 *      nombre es casi idéntico.
	 *   3) Ese candidato gana por un margen claro sobre cualquier otro.
	 * Si los tres se cumplen, la intención del código es inequívoca. Si alguno
	 * falla, devuelve false y el caso sigue el flujo normal con IA.
	 *
	 * @param array $incident Incidencia del registro.
	 * @return array|false
	 */
	/**
	 * ABH-ENV-012 · la misma clase declarada dos veces desde archivos distintos.
	 *
	 * Caso real: dos copias del mismo plugin instaladas en carpetas distintas.
	 * PHP carga la primera, llega a la segunda y detiene el sitio con
	 * «Cannot declare class X, because the name is already in use».
	 *
	 * El arreglo que todo el mundo propone es borrar una de las dos carpetas, y
	 * eso ni cabe dentro de un archivo ni es reversible en un clic. El idioma
	 * estándar de PHP para esto sí cabe: envolver la declaración en
	 * class_exists(). El sitio vuelve a levantar usando la copia que cargó
	 * primero, no se borra nada, y revertir es quitar dos líneas.
	 *
	 * Determinista: no consulta al modelo y no gasta un solo token.
	 *
	 * @param array $incident Incidencia.
	 * @return array|false
	 */
	public static function duplicate_class_fix( $incident ) {
		$msg = isset( $incident['message'] ) ? (string) $incident['message'] : '';
		if ( ! preg_match( '/Cannot declare class\s+(?:[\\\\\w]+\\\\)?([A-Za-z_][A-Za-z0-9_]*)\s*,?\s*because the name is already in use/i', $msg, $m ) ) {
			return false;
		}
		$clase = $m[1];

		$rel = isset( $incident['rel_path'] ) ? ABH_Guard::normalize( $incident['rel_path'] ) : '';
		if ( '' === $rel ) {
			return false;
		}
		$path_check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $path_check['allowed'] ) ) {
			return false;
		}
		$code = ABH_Engine::read_file( $rel );
		if ( false === $code || '' === $code ) {
			return false;
		}

		// Si ya está protegida, no hay nada que hacer. Envolver dos veces sería
		// ruido, y peor: haría creer que se arregló algo.
		if ( preg_match( '/class_exists\s*\(\s*[\'"]' . preg_quote( $clase, '/' ) . '[\'"]/i', $code ) ) {
			return false;
		}

		$rango = self::class_span( $code, $clase );
		if ( false === $rango ) {
			return false;
		}

		$patched = substr( $code, 0, $rango['ini'] )
			. "if ( ! class_exists( '" . $clase . "', false ) ) {\n"
			. substr( $code, $rango['ini'], $rango['fin'] - $rango['ini'] + 1 )
			. "\n}\n"
			. substr( $code, $rango['fin'] + 1 );

		if ( $patched === $code ) {
			return false;
		}

		// Las mismas compuertas que cualquier parche: portero y sintaxis.
		$guard = ABH_Guard::check_content( $code, $patched );
		if ( empty( $guard['allowed'] ) ) {
			return false;
		}
		$lint = ABH_Verifier::lint( $patched );
		if ( empty( $lint['ok'] ) ) {
			return false;
		}

		return array(
			'ok'          => true,
			'clase'       => $clase,
			'rel_path'    => $rel,
			'sha_before'  => hash( 'sha256', $code ),
			'patched'     => $patched,
			'diff'        => ABH_Engine::diff_rows( $code, $patched ),
			'explicacion' => array(
				'tipo'       => 'causa',
				'que_pasa'   => sprintf(
					/* translators: 1: clase, 2: archivo. */
					__( 'PHP found the class %1$s declared a second time in %2$s and stopped the site. A class can only be declared once per request.', 'ai-bug-hunter' ),
					$clase,
					$rel
				),
				'causa_raiz' => sprintf(
					/* translators: %s: clase. */
					__( 'There are two different files declaring %s. Usually this is the same plugin installed twice, in two folders, after a manual update that left the old copy behind.', 'ai-bug-hunter' ),
					$clase
				),
				'que_hace'   => sprintf(
					/* translators: %s: clase. */
					__( 'Wrap the declaration of %s in a class_exists() check. If another copy already declared it, this file skips it instead of taking the site down.', 'ai-bug-hunter' ),
					$clase
				),
				'que_no_arregla' => __( 'It does not delete the duplicate copy or decide which of the two is the right one: the site starts up with whichever loads first. When you can, leave a single folder for the plugin.', 'ai-bug-hunter' ),
				'riesgos'    => __( 'If the two copies have different versions, the one that loads first will stay active. It is reverted by removing the two added lines.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Principio y fin de la declaración de una clase, en bytes.
	 *
	 * Se hace con el analizador de PHP, no con expresiones regulares: hay que
	 * distinguir la declaración real de un `X::class`, de una clase anónima y
	 * del nombre dentro de un comentario o una cadena.
	 *
	 * @param string $code  Código.
	 * @param string $clase Nombre de la clase.
	 * @return array|false  ini, fin (offsets de byte).
	 */
	private static function class_span( $code, $clase ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return false;
		}
		$tokens = token_get_all( $code );
		$off    = 0;
		$offs   = array();
		foreach ( $tokens as $i => $tok ) {
			$offs[ $i ] = $off;
			$off       += strlen( is_array( $tok ) ? $tok[1] : $tok );
		}

		$total = count( $tokens );
		for ( $i = 0; $i < $total; $i++ ) {
			$tok = $tokens[ $i ];
			if ( ! is_array( $tok ) || T_CLASS !== $tok[0] ) {
				continue;
			}
			// `Foo::class` no es una declaración.
			for ( $b = $i - 1; $b >= 0; $b-- ) {
				$prev = $tokens[ $b ];
				if ( is_array( $prev ) && in_array( $prev[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					continue;
				}
				if ( is_array( $prev ) && T_DOUBLE_COLON === $prev[0] ) {
					continue 2;
				}
				break;
			}
			// El nombre que sigue tiene que ser el que buscamos.
			$nombre = '';
			$j      = $i + 1;
			for ( ; $j < $total; $j++ ) {
				$t = $tokens[ $j ];
				if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					continue;
				}
				if ( is_array( $t ) && T_STRING === $t[0] ) {
					$nombre = $t[1];
				}
				break;
			}
			if ( $nombre !== $clase ) {
				continue;
			}

			// El inicio real incluye abstract/final si los hubiera.
			$ini = $offs[ $i ];
			for ( $b = $i - 1; $b >= 0; $b-- ) {
				$prev = $tokens[ $b ];
				if ( is_array( $prev ) && in_array( $prev[0], array( T_WHITESPACE, T_ABSTRACT, T_FINAL ), true ) ) {
					if ( T_WHITESPACE !== $prev[0] ) {
						$ini = $offs[ $b ];
					}
					continue;
				}
				break;
			}

			// Llave de apertura y su pareja.
			$profundidad = 0;
			$abierta     = false;
			for ( $k = $j; $k < $total; $k++ ) {
				$t = $tokens[ $k ];
				$s = is_array( $t ) ? $t[1] : $t;
				if ( '{' === $s || ( is_array( $t ) && in_array( $t[0], array( T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES ), true ) ) ) {
					$profundidad++;
					$abierta = true;
					continue;
				}
				if ( '}' === $s ) {
					$profundidad--;
					if ( $abierta && 0 === $profundidad ) {
						return array( 'ini' => $ini, 'fin' => $offs[ $k ] );
					}
				}
			}
			return false;
		}
		return false;
	}

	public static function code_typo_fix( $incident ) {
		$msg = isset( $incident['message'] ) ? (string) $incident['message'] : '';
		if ( ! preg_match( '/Call to undefined function\s+(?:[\\\\\w]+\\\\)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/i', $msg, $m ) ) {
			return false;
		}
		$bad = $m[1];
		// Si la función existe, el fallo es de carga o de contexto, no un typo.
		if ( function_exists( $bad ) ) {
			return false;
		}

		$rel = isset( $incident['rel_path'] ) ? ABH_Guard::normalize( $incident['rel_path'] ) : '';
		if ( '' === $rel ) {
			return false;
		}
		$path_check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $path_check['allowed'] ) ) {
			return false;
		}
		$code = ABH_Engine::read_file( $rel );
		if ( false === $code || '' === $code ) {
			return false;
		}
		// El símbolo debe aparecer exactamente una vez como llamada: si está en
		// varios sitios, el arreglo deja de ser una sustitución trivial.
		$patron = '/(?<![\w$>:])' . preg_quote( $bad, '/' ) . '\s*\(/';
		if ( 1 !== preg_match_all( $patron, $code ) ) {
			return false;
		}

		// Candidatos: funciones invocadas en el mismo archivo que sí existen.
		preg_match_all( '/(?<![\w$>:])([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $code, $mm );
		$mejor     = '';
		$mejor_pct = 0.0;
		$segundo   = 0.0;
		foreach ( array_unique( $mm[1] ) as $cand ) {
			if ( $cand === $bad || ! function_exists( $cand ) ) {
				continue;
			}
			$pct = 0.0;
			similar_text( strtolower( $bad ), strtolower( $cand ), $pct );
			if ( $pct > $mejor_pct ) {
				$segundo   = $mejor_pct;
				$mejor_pct = $pct;
				$mejor     = $cand;
			} elseif ( $pct > $segundo ) {
				$segundo = $pct;
			}
		}
		// Umbrales conservadores: parecido alto y ventaja clara sobre el resto.
		if ( '' === $mejor || $mejor_pct < 65.0 || ( $mejor_pct - $segundo ) < 10.0 ) {
			return false;
		}

		$patched = preg_replace( $patron, $mejor . '(', $code, 1 );
		if ( null === $patched || $patched === $code ) {
			return false;
		}

		// Las mismas compuertas que cualquier parche: portero y sintaxis.
		$guard = ABH_Guard::check_content( $code, $patched );
		if ( empty( $guard['allowed'] ) ) {
			return false;
		}
		$lint = ABH_Verifier::lint( $patched );
		if ( empty( $lint['ok'] ) ) {
			return false;
		}

		return array(
			'ok'          => true,
			'bad'         => $bad,
			'good'        => $mejor,
			'similitud'   => round( $mejor_pct, 1 ),
			'rel_path'    => $rel,
			'sha_before'  => hash( 'sha256', $code ),
			'patched'     => $patched,
			'diff'        => ABH_Engine::diff_rows( $code, $patched ),
			'explicacion' => array(
				'tipo'         => 'causa',
				'que_pasa'     => sprintf(
					/* translators: 1: función inexistente, 2: archivo. */
					__( 'The code calls %1$s(), a function that does not exist in this installation, and PHP stops execution with a fatal error in %2$s.', 'ai-bug-hunter' ),
					$bad,
					$rel
				),
				'causa_raiz'   => sprintf(
					/* translators: 1: función mal escrita, 2: función correcta, 3: parecido. */
					__( 'The name is misspelled: %1$s() is not defined anywhere in the runtime, while %2$s() does exist and is already used in this same file (%3$s%% similar). The intent of the code is unmistakable.', 'ai-bug-hunter' ),
					$bad,
					$mejor,
					round( $mejor_pct, 1 )
				),
				'que_hace'     => sprintf(
					/* translators: 1: función mal escrita, 2: función correcta. */
					__( 'Corrects the name %1$s() to %2$s() in that single call. It does not change any other line.', 'ai-bug-hunter' ),
					$bad,
					$mejor
				),
				'que_no'       => __( 'It does not explain why the incorrect name was introduced. If the file was altered by a third party, it is worth comparing the plugin with its official version.', 'ai-bug-hunter' ),
				'riesgos'      => __( 'Minimal: it restores a call to a function that already exists and that the file itself uses on another line.', 'ai-bug-hunter' ),
				'verificacion' => __( 'The fatal error must disappear and the affected functionality must respond again.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Repara un archivo devolviéndolo a su original oficial.
	 *
	 * Determinista y sin tokens. Es la vía correcta cuando el archivo pertenece
	 * a un plugin o tema con fuente oficial: no se reconstruye razonando, se
	 * compara y se restituye.
	 *
	 * Existe porque razonar falla justo donde más caro sale. Si el daño borró
	 * información — un nombre de filtro, una llamada entera — no queda nada en
	 * el archivo de donde deducirla. Un modelo la adivinaría; el original la
	 * sabe. Y en una plantilla de pago, adivinar no es una opción.
	 *
	 * Compuertas: la ruta debe estar dentro del área escribible, el archivo debe
	 * tener origen oficial identificable, y debe diferir del original.
	 *
	 * @param array $incident Incidencia del registro.
	 * @return array|false
	 */
	public static function official_restore_fix( $incident ) {
		if ( ! class_exists( 'ABH_Source' ) ) {
			return false;
		}
		$rel = isset( $incident['rel_path'] ) ? ABH_Guard::normalize( $incident['rel_path'] ) : '';
		if ( '' === $rel ) {
			return false;
		}
		$check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $check['allowed'] ) ) {
			return false;
		}
		$oficial = ABH_Source::official_file( $rel );
		if ( false === $oficial ) {
			return false;
		}
		$code = ABH_Engine::read_file( $rel );
		if ( false === $code || $code === $oficial['content'] ) {
			return false;
		}

		$patched = $oficial['content'];
		// El original oficial pasa por las mismas compuertas que cualquier
		// parche. Si el propio WordPress.org sirviera algo que no compila, no
		// se escribe: la procedencia no exime de comprobar.
		$lint = ABH_Verifier::lint( $patched );
		if ( empty( $lint['ok'] ) ) {
			return false;
		}

		$origen  = $oficial['origen'];
		$etiqueta = 'manifiesto' === $oficial['confianza']
			? __( 'its sha256 fingerprint published by WordPress.org matches exactly', 'ai-bug-hunter' )
			: __( 'it comes from the official WordPress.org package, although that source does not publish a per-file fingerprint', 'ai-bug-hunter' );

		return array(
			'ok'         => true,
			'origen'     => $origen,
			'confianza'  => $oficial['confianza'],
			'rel_path'   => $rel,
			'sha_before' => hash( 'sha256', $code ),
			'patched'    => $patched,
			'diff'       => ABH_Engine::diff_rows( $code, $patched ),
			'explicacion' => array(
				'tipo'       => 'causa',
				'que_pasa'   => sprintf(
					/* translators: 1: ruta, 2: slug, 3: versión. */
					__( '%1$s does not match the original from %2$s %3$s. The installed file was modified and in its current state it breaks execution.', 'ai-bug-hunter' ),
					$rel,
					$origen['slug'],
					$origen['version']
				),
				'causa_raiz' => sprintf(
					/* translators: 1: ruta, 2: slug, 3: versión, 4: cómo se verificó. */
					__( 'There is no need to guess what broke: %1$s has a published original. I compared your copy with the one from %2$s %3$s and they differ. That original is reliable because %4$s.', 'ai-bug-hunter' ),
					$rel,
					$origen['slug'],
					$origen['version'],
					$etiqueta
				),
				'que_hace'   => __( 'It replaces the whole file with its official content. It does not invent code or reconstruct anything: it copies the original as is.', 'ai-bug-hunter' ),
				'que_no'     => __( 'If you had customized this file on purpose, those changes are lost: they remain in the backup and you can recover them from History. Customizing plugins by editing their files is always lost in the next update; the right way is to override the template from your theme.', 'ai-bug-hunter' ),
				'riesgos'    => __( 'Low: the content being written is exactly what the plugin\'s own author published for the version you already have installed.', 'ai-bug-hunter' ),
				'verificacion' => __( 'The affected page should load again and the syntax error should disappear from the log.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Repara una llamada a método private/protected desde otra clase.
	 *
	 * Determinista y sin tokens. Es la familia de fallo que aparece al partir
	 * una clase: un método queda private en la clase extraída y se sigue
	 * invocando desde fuera. php -l no la ve, porque la sintaxis es válida.
	 *
	 * Ampliar visibilidad no altera firma, retorno ni comportamiento, así que
	 * el arreglo correcto y mínimo es subir ese único método a public.
	 *
	 * Compuertas, todas obligatorias:
	 *  - El mensaje debe nombrar clase, método y ámbito llamador.
	 *  - El ámbito llamador debe ser distinto de la clase declarante: si fuera
	 *    la misma, el error sería otro y el arreglo sería otro.
	 *  - Se localiza el archivo que DECLARA el método, no el que lo llama.
	 *  - La declaración debe aparecer exactamente una vez en ese archivo.
	 *  - El disco debe confirmar la visibilidad que dice el error.
	 *
	 * @param array $incident Incidencia del registro.
	 * @return array|false
	 */
	public static function visibility_fix( $incident ) {
		$msg = isset( $incident['message'] ) ? (string) $incident['message'] : '';
		$re  = '/Call to (private|protected) method ([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*from\s+(global\s+scope|scope\s+([A-Za-z_\\\\][A-Za-z0-9_\\\\]*))/i';
		if ( ! preg_match( $re, $msg, $m ) ) {
			return false;
		}
		$vis     = strtolower( $m[1] );
		$clase   = ltrim( $m[2], '\\' );
		$metodo  = $m[3];
		$llamador = isset( $m[5] ) ? ltrim( $m[5], '\\' ) : '';

		// Mismo ámbito: no es un problema de visibilidad entre clases.
		if ( '' !== $llamador && 0 === strcasecmp( $llamador, $clase ) ) {
			return false;
		}

		$rel = self::declaring_file( $clase, $metodo );
		if ( '' === $rel ) {
			return false;
		}
		$check = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
		if ( empty( $check['allowed'] ) ) {
			return false;
		}
		$code = ABH_Engine::read_file( $rel );
		if ( false === $code || '' === $code ) {
			return false;
		}

		// La declaración debe ser única: con dos, el parche deja de ser trivial.
		// PHP acepta los modificadores en cualquier orden: 'private static' y
		// 'static private' son ambos válidos. El patrón tiene que ver los dos, o
		// se abstendría en un caso perfectamente legítimo.
		$patron = '/(^[ \t]*(?:(?:final|abstract)\s+)?(?:static\s+)?)(' . $vis . ')(\s+(?:static\s+)?function\s+&?\s*' . preg_quote( $metodo, '/' ) . '\s*\()/mi';
		if ( 1 !== preg_match_all( $patron, $code ) ) {
			return false;
		}
		// Y el archivo debe declarar de verdad esa clase.
		if ( ! preg_match( '/\b(?:class|trait)\s+' . preg_quote( self::short_name( $clase ), '/' ) . '\b/i', $code ) ) {
			return false;
		}

		$patched = preg_replace( $patron, '${1}public${3}', $code, 1 );
		if ( null === $patched || $patched === $code ) {
			return false;
		}

		// Las mismas compuertas que cualquier parche: portero y sintaxis.
		$guard = ABH_Guard::check_content( $code, $patched );
		if ( empty( $guard['allowed'] ) ) {
			return false;
		}
		$lint = ABH_Verifier::lint( $patched );
		if ( empty( $lint['ok'] ) ) {
			return false;
		}

		$simbolo = $clase . '::' . $metodo . '()';
		$desde   = '' !== $llamador ? $llamador : __( 'the global scope', 'ai-bug-hunter' );

		return array(
			'ok'         => true,
			'clase'      => $clase,
			'metodo'     => $metodo,
			'visibilidad' => $vis,
			'llamador'   => $llamador,
			'rel_path'   => $rel,
			'sha_before' => hash( 'sha256', $code ),
			'patched'    => $patched,
			'diff'       => ABH_Engine::diff_rows( $code, $patched ),
			'explicacion' => array(
				'tipo'       => 'causa',
				'que_pasa'   => sprintf(
					/* translators: 1: símbolo, 2: visibilidad, 3: quién llama. */
					__( '%1$s is declared as %2$s, but it is called from %3$s. PHP kills the whole request with a fatal error as soon as that line runs.', 'ai-bug-hunter' ),
					$simbolo,
					$vis,
					$desde
				),
				'causa_raiz' => sprintf(
					/* translators: 1: símbolo, 2: visibilidad, 3: archivo. */
					__( 'The declaration of %1$s in %3$s is %2$s, so only its own class can call it. This is the typical failure after moving code from one class to another: the call is left outside and the visibility is not adjusted. The syntax is still valid, which is why static analysis does not catch it.', 'ai-bug-hunter' ),
					$simbolo,
					$vis,
					$rel
				),
				'que_hace'   => sprintf(
					/* translators: 1: visibilidad actual, 2: símbolo. */
					__( 'Changes %1$s to public in that single declaration of %2$s. It does not touch the body of the method, its signature, or any other line in the file.', 'ai-bug-hunter' ),
					$vis,
					$simbolo
				),
				'que_no'     => __( 'It does not decide whether that method should be public by design. If the intention was to keep it internal, the right move is to bring the call inside the class; this fix restores the behavior, it does not redesign the architecture.', 'ai-bug-hunter' ),
				'riesgos'    => __( 'Widening the visibility does not change the signature, the return value or the behavior of the method: it only allows it to be called from outside, which is exactly what the code was already trying to do.', 'ai-bug-hunter' ),
				'verificacion' => __( 'The fatal error must disappear and the affected screen or function must load again.', 'ai-bug-hunter' ),
			),
		);
	}

	/**
	 * Nombre corto de una clase con espacio de nombres.
	 *
	 * @param string $clase Nombre completo.
	 * @return string
	 */
	private static function short_name( $clase ) {
		$pos = strrpos( $clase, '\\' );
		return false === $pos ? $clase : substr( $clase, $pos + 1 );
	}

	/**
	 * Archivo que declara un método, no el que lo llama.
	 *
	 * El error fatal nombra el archivo donde ocurre la llamada. El que hay que
	 * corregir es el otro. La reflexión da la respuesta exacta cuando la clase
	 * está cargada; si no lo está, se abstiene en vez de adivinar.
	 *
	 * @param string $clase  Clase.
	 * @param string $metodo Método.
	 * @return string Ruta relativa, o cadena vacía.
	 */
	private static function declaring_file( $clase, $metodo ) {
		if ( ! class_exists( $clase ) && ! trait_exists( $clase ) ) {
			return '';
		}
		try {
			$ref = new ReflectionMethod( $clase, $metodo );
		} catch ( Throwable $e ) {
			return '';
		}
		$abs = (string) $ref->getFileName();
		if ( '' === $abs || ! is_readable( $abs ) ) {
			return '';
		}
		$abs  = wp_normalize_path( $abs );
		$raiz = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
		if ( 0 !== strpos( $abs, $raiz ) ) {
			return '';
		}
		return substr( $abs, strlen( $raiz ) );
	}

	/**
	 * Aplica la corrección de permisos, con respaldo del modo anterior.
	 *
	 * @param array  $diag          Diagnóstico devuelto por diagnose().
	 * @param string $incident_key  Clave de la incidencia, para poder marcarla resuelta después.
	 * @return array ok, message, op_id
	 */
	public static function apply_fix( $diag, $incident_key = '' ) {
		if ( empty( $diag['fixable'] ) || empty( $diag['fix'] ) || 'chmod' !== $diag['fix']['type'] ) {
			return array(
				'ok'      => false,
				'message' => __( 'This diagnosis cannot be fixed automatically. Follow the steps shown.', 'ai-bug-hunter' ),
			);
		}

		$original = wp_normalize_path( (string) $diag['fix']['path'] );
		$mode     = (int) $diag['fix']['mode'];
		$rel      = self::rel_of( $original );
		$path     = '' !== $rel ? ABH_Guard::resolve_existing_path( $rel, ABH_Engine::writable_roots() ) : false;

		// Ese resolutor solo conoce wp-content, así que convertía el registro en
		// «false» antes de que nadie llegara a evaluarlo. Si no resuelve por ahí,
		// se conserva la ruta original y decide env_fixable(), que es el único
		// criterio: no se abre nada, solo se deja de cerrar por partida doble.
		if ( ! $path ) {
			$path = $original;
		}

		if ( '' === $path || ! self::env_fixable( $path ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That path is protected: the plugin does not change its permissions.', 'ai-bug-hunter' ),
			);
		}
		if ( ! @file_exists( $path ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The path no longer exists.', 'ai-bug-hunter' ),
			);
		}

		// Nunca más permisivo de lo previsto.
		$permitidos = array( self::MODE_PRIVATE_FILE, self::MODE_FILE, self::MODE_DIR );
		if ( ! in_array( $mode, $permitidos, true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Target permissions not allowed.', 'ai-bug-hunter' ),
			);
		}

		$antes = @fileperms( $path );
		if ( false === $antes ) {
			return array(
				'ok'      => false,
				'message' => __( 'The current permissions could not be read. Nothing is being changed, because there would be no way to guarantee the rollback.', 'ai-bug-hunter' ),
			);
		}
		$antes = $antes & 0777;

		if ( ! @chmod( $path, $mode ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: permisos destino. */
					__( 'The server did not allow the permissions to be changed. Do it yourself from your file manager or over FTP: %s.', 'ai-bug-hunter' ),
					substr( sprintf( '%o', $mode ), -3 )
				),
			);
		}

		clearstatcache( true, $path );

		$op = ABH_Backup::record(
			array(
				'op_id'        => substr( md5( $path . microtime( true ) . wp_rand() ), 0, 12 ),
				'action'       => 'chmod',
				'rel_path'     => $rel,
				'incident_key' => $incident_key,
				'abs_path'     => $path,
				'mode_before' => $antes,
				'mode_after'  => $mode,
				'model'       => self::SIGNATURE,
				'incident'    => isset( $diag['code'] ) ? $diag['code'] : '',
				'diagnosis'   => sprintf(
					/* translators: 1: permisos anteriores, 2: permisos nuevos. */
					__( 'Permissions fixed from %1$s to %2$s (HUNTER AI local).', 'ai-bug-hunter' ),
					substr( sprintf( '%o', $antes ), -3 ),
					substr( sprintf( '%o', $mode ), -3 )
				),
			)
		);

		return array(
			'ok'      => true,
			'op_id'   => $op['op_id'],
			'message' => sprintf(
				/* translators: 1: ruta, 2: permisos nuevos. */
				__( 'Permissions fixed: %1$s is now %2$s.', 'ai-bug-hunter' ),
				$rel,
				substr( sprintf( '%o', $mode ), -3 )
			),
		);
	}
}
