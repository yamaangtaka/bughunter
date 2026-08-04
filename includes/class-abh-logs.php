<?php
/**
 * Lectura y triage del registro de errores de PHP.
 *
 * El 90% del trabajo de clasificación se hace aquí con expresiones regulares,
 * sin gastar un solo token de IA.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Lee y reescribe el registro de errores del sitio.
 *
 * POR QUE EXISTE:  El registro es la evidencia. Poder vaciarlo es parte de cerrar un incidente.
 *
 * SI LO RECORTAS:  OJO: el contenido del registro es entrada CONTROLADA POR EL ATACANTE. Cualquiera que provoque un error escribe texto ahí, y ese texto viaja al modelo. Trátalo siempre como datos, nunca como instrucciones.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Large logs are read as bounded streams and never loaded in full; direct readability checks are part of the diagnostic evidence.

/**
 * Class ABH_Logs
 */
class ABH_Logs {

	const MAX_LINES = 3000;

	/**
	 * Tope duro de bytes que se leen del final del registro.
	 *
	 * El registro lo engorda cualquiera que provoque errores, así que su tamaño
	 * es entrada hostil. Sin tope, la pantalla principal del plugin —que lee el
	 * registro en cada carga— se caía sola con un registro de cientos de megas y
	 * no quedaba forma de vaciarlo desde la interfaz, porque la interfaz ya no
	 * abría. Se lee solo la cola, que es donde están los errores recientes.
	 */
	const MAX_BYTES = 524288;

	/**
	 * Tope de caracteres por línea. Una sola línea puede traer un volcado
	 * enorme; se recorta por el medio para no perder la cola, que es donde PHP
	 * escribe el archivo y la línea del error.
	 */
	const MAX_LINE_CHARS = 2000;

	/**
	 * Tope de incidencias distintas que se devuelven de una lectura.
	 *
	 * Quien provoca errores escribe en el registro sin estar autenticado, y cada
	 * incidencia de sintaxis le cuesta a la pantalla principal una lectura
	 * completa del archivo señalado más un análisis del código. Con miles de
	 * incidencias distintas —fáciles de fabricar variando el texto del error— la
	 * pantalla se caía sola por tiempo agotado. Se corta la lista después de
	 * ordenarla por gravedad, así que lo que sobrevive al tope es lo peor, no lo
	 * primero que apareció, y se avisa en pantalla de que se cortó.
	 */
	const MAX_INCIDENTS = 200;

	/**
	 * Tope de rutas distintas memorizadas por petición al comprobar sintaxis.
	 */
	const MAX_LINT_CACHE = 400;

	/**
	 * Bytes que se leen de golpe del registro. fgets() sin tope lee hasta el
	 * salto de línea, y una línea sin saltos puede traerse el archivo entero.
	 */
	const READ_CHUNK = 65536;

	/**
	 * Tope de bytes que un solo bloque puede acumular antes de volcarse.
	 * Es lo que mantiene la limpieza selectiva con memoria constante.
	 */
	const MAX_BLOCK_BYTES = 262144;

	/**
	 * Prefijo con el que nace el archivo temporal de la limpieza selectiva.
	 *
	 * Es lo único que permite distinguir un temporal NUESTRO de cualquier otro
	 * archivo de la carpeta del registro, así que el barrido de huérfanos no
	 * borra nada que no case exactamente con este prefijo.
	 */
	const TEMP_PREFIX = 'abh-log-';

	/**
	 * Edad mínima, en segundos, para que un temporal se considere huérfano.
	 *
	 * Seis horas. El temporal de una limpieza viva se toca en cada escritura,
	 * así que su fecha de modificación se refresca mientras el trabajo avanza;
	 * para que el barrido lo alcance tendría que estar quieto seis horas. Ningún
	 * hosting deja correr una petición web tanto tiempo —lo normal son 30 a 300
	 * segundos de max_execution_time, y hasta detrás de un proxy colgado se
	 * habla de minutos—, de modo que el margen es de al menos un orden de
	 * magnitud sobre el peor caso realista y una ejecución concurrente nunca
	 * puede quedarse sin su temporal. Bajarlo mucho volvería el barrido
	 * destructivo; subirlo mucho dejaría el disco lleno más tiempo del necesario.
	 */
	const TEMP_MAX_AGE = 21600;

	/**
	 * Temporales vivos de ESTA petición: ruta => firma del archivo (dispositivo
	 * e inodo) tomada al crearlo. Lo lee el cierre de emergencia.
	 *
	 * @var array
	 */
	private static $temp_guard = array();

	/**
	 * ¿Ya se registró el cierre de emergencia? Se registra una sola vez.
	 *
	 * @var bool
	 */
	private static $temp_hooked = false;

	/**
	 * ¿La última lectura tuvo que recortar algo? Se avisa en pantalla: un
	 * registro recortado en silencio hace creer que no hay más errores.
	 *
	 * @var bool
	 */
	private static $trimmed = false;

	/**
	 * ¿El último análisis llegó al tope de incidencias? También se avisa.
	 *
	 * @var bool
	 */
	private static $capped = false;

	/**
	 * Veredicto de sintaxis ya calculado, por ruta canónica, durante ESTA
	 * petición. La clave se forma con la ruta que devuelve el guardián —nunca
	 * con el texto del registro— más la fecha y el tamaño del archivo, para que
	 * un arreglo aplicado a media petición no siga leyéndose del recuerdo.
	 *
	 * @var array
	 */
	private static $lint_cache = array();

	/**
	 * ¿Se recortó la última lectura del registro?
	 *
	 * @return bool
	 */
	public static function was_trimmed() {
		return self::$trimmed;
	}

	/**
	 * ¿El último análisis dejó incidencias fuera por el tope?
	 *
	 * @return bool
	 */
	public static function was_capped() {
		return self::$capped;
	}

	/**
	 * Severidad por tipo de error.
	 *
	 * @return array
	 */
	public static function severities() {
		return array(
			'parse error'             => 100,
			'fatal error'             => 95,
			'recoverable fatal error' => 90,
			'warning'                 => 50,
			'deprecated'              => 30,
			'notice'                  => 20,
		);
	}

	/**
	 * Rutas candidatas del log, en orden de preferencia.
	 *
	 * @return array
	 */
	public static function candidate_paths() {
		$paths = array();

		// Un registro externo solo se admite cuando el propietario del servidor lo
		// fija expresamente en wp-config.php. Esto evita leer o vaciar registros
		// globales de PHP que pueden contener datos de otros sitios del hosting.
		if ( defined( 'ABH_TRUSTED_LOG_PATH' ) && is_string( ABH_TRUSTED_LOG_PATH ) && '' !== trim( ABH_TRUSTED_LOG_PATH ) ) {
			$paths[] = ABH_TRUSTED_LOG_PATH;
		}

		$ini = ini_get( 'error_log' );
		if ( $ini && '' !== trim( $ini ) && 'syslog' !== $ini ) {
			$paths[] = $ini;
		}

		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$paths[] = WP_DEBUG_LOG;
		}

		$paths[] = WP_CONTENT_DIR . '/debug.log';
		$paths[] = ABSPATH . 'error_log';
		$paths[] = ABSPATH . 'php_errorlog';
		$paths[] = WP_CONTENT_DIR . '/error_log';

		$out = array();
		foreach ( $paths as $p ) {
			$p = wp_normalize_path( $p );
			if ( ! in_array( $p, $out, true ) ) {
				$out[] = $p;
			}
		}
		return $out;
	}

	/**
	 * Resuelve un registro autorizado. Por defecto debe vivir dentro de la raíz
	 * real de WordPress y no atravesar enlaces simbólicos. Un único registro
	 * externo puede autorizarse mediante ABH_TRUSTED_LOG_PATH.
	 *
	 * @param string $path Ruta candidata.
	 * @return string|false Ruta canónica.
	 */
	public static function resolve_trusted_path( $path ) {
		$path = wp_normalize_path( (string) $path );
		if ( '' === $path || is_link( $path ) || ! file_exists( $path ) ) {
			return false;
		}
		$real = realpath( $path );
		if ( false === $real ) {
			return false;
		}
		$real = wp_normalize_path( $real );

		if ( defined( 'ABH_TRUSTED_LOG_PATH' ) && is_string( ABH_TRUSTED_LOG_PATH ) ) {
			$trusted = wp_normalize_path( trim( ABH_TRUSTED_LOG_PATH ) );
			$trusted_real = '' !== $trusted && ! is_link( $trusted ) && file_exists( $trusted ) ? realpath( $trusted ) : false;
			if ( false !== $trusted_real && hash_equals( wp_normalize_path( $trusted_real ), $real ) ) {
				return $real;
			}
		}

		$rel = self::to_relative( $real );
		if ( '' === $rel ) {
			return false;
		}
		$resolved = ABH_Guard::resolve_existing_path( $rel, null );
		return false !== $resolved && hash_equals( wp_normalize_path( $resolved ), $real ) ? $real : false;
	}

	/**
	 * Devuelve la primera ruta de log existente y legible.
	 *
	 * @return string|false
	 */
	public static function find_log() {
		foreach ( self::candidate_paths() as $p ) {
			$trusted = self::resolve_trusted_path( $p );
			if ( $trusted && @is_readable( $trusted ) && @filesize( $trusted ) > 0 ) {
				return $trusted;
			}
		}
		return false;
	}

	/**
	 * Lee las últimas líneas de un archivo sin cargarlo entero en memoria.
	 *
	 * Tres topes, todos duros: bytes leídos, número de líneas y longitud de cada
	 * línea. Ninguno depende del contenido del registro, que es entrada que
	 * controla quien provoca los errores.
	 *
	 * @param string $file  Ruta.
	 * @param int    $lines Número de líneas.
	 * @return string
	 */
	public static function tail( $file, $lines = self::MAX_LINES ) {
		self::$trimmed = false;

		$fh = @fopen( $file, 'rb' );
		if ( ! $fh ) {
			return '';
		}
		$lines = max( 1, (int) $lines );
		$size  = 0;
		if ( 0 === fseek( $fh, 0, SEEK_END ) ) {
			$size = (int) ftell( $fh );
		}

		// Solo la cola: nunca se recorre el archivo entero, así que el coste no
		// crece con lo que haya acumulado el registro.
		$inicio = $size > self::MAX_BYTES ? $size - self::MAX_BYTES : 0;
		if ( $inicio > 0 ) {
			self::$trimmed = true;
		}
		if ( 0 !== fseek( $fh, $inicio, SEEK_SET ) ) {
			fclose( $fh );
			return '';
		}

		$trozos = array();
		$leidos = 0;
		while ( ! feof( $fh ) && $leidos < self::MAX_BYTES ) {
			$pide  = min( 8192, self::MAX_BYTES - $leidos );
			$chunk = fread( $fh, $pide );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$leidos  += strlen( $chunk );
			$trozos[] = $chunk;
		}
		fclose( $fh );

		$all = explode( "\n", implode( '', $trozos ) );
		unset( $trozos );
		if ( $inicio > 0 ) {
			// La primera línea del trozo está cortada por la mitad: se descarta.
			array_shift( $all );
		}
		if ( count( $all ) > $lines ) {
			$all           = array_slice( $all, -$lines );
			self::$trimmed = true;
		}
		foreach ( $all as $i => $linea ) {
			$all[ $i ] = self::clip_line( $linea );
		}
		return implode( "\n", $all );
	}

	/**
	 * Recorta una línea demasiado larga conservando su cola.
	 *
	 * El final de la línea es donde PHP escribe «in ARCHIVO on line N»: cortar
	 * por el final dejaría la incidencia sin ubicación. Es idempotente a
	 * propósito —el resultado nunca supera el tope—, porque la misma línea pasa
	 * por aquí al mostrarla y al calcular su clave, y las dos rutas tienen que
	 * llegar al mismo texto o la limpieza selectiva dejaría de reconocerla.
	 *
	 * @param string $linea Línea.
	 * @return string
	 */
	private static function clip_line( $linea ) {
		$linea = (string) $linea;
		if ( strlen( $linea ) <= self::MAX_LINE_CHARS ) {
			return $linea;
		}
		self::$trimmed = true;
		$marca  = ' [...] ';
		$cola   = 600;
		$cabeza = self::MAX_LINE_CHARS - $cola - strlen( $marca );
		return substr( $linea, 0, $cabeza ) . $marca . substr( $linea, -$cola );
	}

	/**
	 * Convierte la ruta absoluta del log en ruta relativa a la raíz de WordPress.
	 *
	 * @param string $abs Ruta absoluta.
	 * @return string
	 */
	public static function to_relative( $abs ) {
		$abs  = wp_normalize_path( (string) $abs );
		$root = rtrim( wp_normalize_path( ABSPATH ), '/' );
		if ( ! ABH_Guard::absolute_in_root( $abs, $root ) ) {
			return '';
		}
		return ltrim( substr( $abs, strlen( $root ) ), '/' );
	}

	/**
	 * Carpetas donde se admite la ruta que señala el registro.
	 *
	 * La frontera de ESCRITURA la fija ABH_Engine::writable_roots(), clavada
	 * dentro de wp-content. Para SEÑALAR un archivo se admiten además las
	 * carpetas del núcleo y los archivos sueltos de la raíz de WordPress: un
	 * fatal en wp-includes/ o una constante repetida en wp-config.php son
	 * diagnósticos legítimos. Son de LECTURA y nada más: quien escribe sigue
	 * siendo el motor, con su propia lista, y esta no la amplía.
	 *
	 * @return array
	 */
	private static function location_roots() {
		$roots = class_exists( 'ABH_Engine' ) ? ABH_Engine::writable_roots() : array( 'wp-content/' );

		$roots[] = 'wp-admin/';
		$roots[] = 'wp-includes/';

		// Hay instalaciones con la carpeta de contenido renombrada; el registro
		// sigue nombrándola y sin esto el diagnóstico se quedaría mudo.
		if ( class_exists( 'ABH_Limits' ) ) {
			$contenido = trim( (string) ABH_Limits::content_rel(), '/' );
			if ( '' !== $contenido ) {
				$roots[] = $contenido . '/';
			}
		}

		return array_values( array_unique( $roots ) );
	}

	/**
	 * Convierte la ruta que dice el registro en una ruta canónica de confianza.
	 *
	 * El texto del registro lo escribe cualquiera que provoque un error, así que
	 * esta ruta es entrada hostil. Antes se guardaba tal cual en la incidencia y
	 * la contención quedaba en manos de cada consumidor —y varios abren el
	 * archivo sin raíces—. Se corta aquí, en el origen: lo que no resuelve
	 * dentro de una raíz admitida no llega a existir como ubicación.
	 *
	 * @param string $candidato Ruta tal cual aparece en el registro.
	 * @return array file, rel. Vacíos si la ruta no es de fiar.
	 */
	private static function safe_location( $candidato ) {
		$vacio = array( 'file' => '', 'rel' => '' );
		$abs   = wp_normalize_path( (string) $candidato );
		if ( '' === $abs || ! class_exists( 'ABH_Guard' ) ) {
			return $vacio;
		}

		$rel = self::to_relative( $abs );
		if ( '' === $rel ) {
			// Hay instalaciones cuya raíz se sirve a través de un enlace
			// simbólico: el registro escribe la ruta REAL y ABSPATH es la del
			// enlace. Se reintenta contra la raíz canónica antes de descartar.
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
			return $vacio;
		}

		// resolve_existing_path() exige que el archivo exista, rechaza cualquier
		// enlace simbólico por el camino y comprueba que lo canónico siga dentro
		// de la raíz de WordPress.
		$real = ABH_Guard::resolve_existing_path( $rel, null );
		if ( false === $real ) {
			return $vacio;
		}

		foreach ( self::location_roots() as $root ) {
			if ( ABH_Guard::path_in_root( $rel, $root ) ) {
				return array( 'file' => $real, 'rel' => $rel );
			}
		}
		// Archivo suelto en la raíz de WordPress (wp-config.php, index.php...):
		// se admite para señalarlo, nunca como destino de escritura.
		return false === strpos( $rel, '/' ) ? array( 'file' => $real, 'rel' => $rel ) : $vacio;
	}

	/**
	 * Extrae la ubicación del mensaje: archivo canónico y número de línea.
	 *
	 * Se busca ANCLADO al final de la línea —PHP escribe la ubicación al final,
	 * y Apache le añade como mucho «, referer: ...»— y se usa la ÚLTIMA
	 * coincidencia. Antes valía la primera y sin anclaje: bastaba con provocar
	 * un error cuyo texto llevara « in ARCHIVO on line N» para que el panel
	 * señalara el archivo que quisiera el atacante.
	 *
	 * @param string $msg Mensaje del error.
	 * @return array file, rel, line
	 */
	private static function locate( $msg ) {
		$vacio = array( 'file' => '', 'rel' => '', 'line' => 0 );
		$rx    = '/\bin\s+(?P<file>[^\s\'"]+?\.php)(?:\s+on\s+line\s+|:)(?P<line>\d+)(?=\s*(?:,|$))/i';
		if ( ! preg_match_all( $rx, (string) $msg, $todas, PREG_SET_ORDER ) ) {
			return $vacio;
		}
		$ultima = $todas[ count( $todas ) - 1 ];
		$sitio  = self::safe_location( $ultima['file'] );
		if ( '' === $sitio['file'] ) {
			return $vacio;
		}
		return array(
			'file' => $sitio['file'],
			'rel'  => $sitio['rel'],
			'line' => (int) $ultima['line'],
		);
	}

	/**
	 * Clave de agrupación de una incidencia.
	 *
	 * La calculan el análisis y la limpieza selectiva, y tienen que coincidir
	 * exactamente: si se separan, la limpieza deja de reconocer lo que el panel
	 * dio por resuelto. Por eso vive en un solo sitio.
	 *
	 * @param string $kind Tipo de error.
	 * @param string $rel  Ruta relativa ya validada.
	 * @param int    $line Línea.
	 * @param string $msg  Mensaje.
	 * @return string
	 */
	private static function incident_key( $kind, $rel, $line, $msg ) {
		$norm = preg_replace( '/0x[0-9a-f]+/i', '0xADDR', (string) $msg );
		$norm = preg_replace( '/\b\d{3,}\b/', 'N', $norm );
		// Los modificadores de visibilidad se neutralizan SOLO para agrupar:
		// el mismo símbolo, en el mismo archivo y línea, es un único defecto
		// aunque el mensaje diga "private" en unas apariciones y "protected"
		// en otras (ocurre cuando un arreglo previo cambió la visibilidad).
		// Sin esto, un mismo error se partía en dos incidencias y la variante
		// antigua ya no tenía anclaje en el código: parecía "no reparar".
		$sig = preg_replace( '/\b(private|protected|public)\b/i', 'VIS', $norm );
		return md5( strtolower( (string) $kind ) . '|' . (string) $rel . '|' . (int) $line . '|' . substr( $sig, 0, 200 ) );
	}

	/**
	 * Parsea el contenido de un log y devuelve incidencias deduplicadas.
	 *
	 * @param string $text Contenido.
	 * @return array
	 */
	public static function parse( $text ) {
		self::$capped = false;

		$lines = explode( "\n", str_replace( "\r\n", "\n", $text ) );
		$found = array();
		$sev   = self::severities();

		$rx_line = '/^\[(?P<ts>[^\]]+)\]\s+(?:PHP\s+)?(?P<kind>Parse error|Fatal error|Recoverable fatal error|Warning|Notice|Deprecated)\s*:\s*(?P<msg>.*)$/i';

		foreach ( $lines as $raw ) {
			$raw = self::clip_line( trim( $raw ) );
			if ( '' === $raw ) {
				continue;
			}
			if ( ! preg_match( $rx_line, $raw, $m ) ) {
				continue;
			}

			$kind = trim( $m['kind'] );
			$msg  = trim( $m['msg'] );
			$ts   = trim( $m['ts'] );

			$loc  = self::locate( $msg );
			$file = $loc['file'];
			$rel  = $loc['rel'];
			$line = $loc['line'];

			$key = self::incident_key( $kind, $rel, $line, $msg );

			if ( isset( $found[ $key ] ) ) {
				$found[ $key ]['count']++;
				$found[ $key ]['last_ts']   = $ts;
				$found[ $key ]['last_unix'] = self::ts_to_unix( $ts );
				continue;
			}

			$found[ $key ] = array(
				'key'       => $key,
				'kind'      => $kind,
				'message'   => $msg,
				'short'     => self::short_message( $msg ),
				'file'      => $file,
				'rel_path'  => $rel,
				'line'      => $line,
				'count'     => 1,
				'first_ts'  => $ts,
				'last_ts'   => $ts,
				'last_unix' => self::ts_to_unix( $ts ),
				'severity'  => isset( $sev[ strtolower( $kind ) ] ) ? $sev[ strtolower( $kind ) ] : 40,
			);
		}

		$out = array_values( $found );
		unset( $found );

		// Se ordena ANTES de aplicar el tope: quien llena el registro no elige
		// así qué incidencia se queda fuera. Lo que sobrevive es lo más grave.
		usort(
			$out,
			function ( $a, $b ) {
				if ( $a['severity'] === $b['severity'] ) {
					return $b['count'] - $a['count'];
				}
				return $b['severity'] - $a['severity'];
			}
		);

		// El tope acota también el trabajo de todo lo que viene después: la
		// marca de histórico de aquí abajo pregunta al disco por cada incidencia,
		// y la pantalla principal analiza el archivo de cada una.
		if ( count( $out ) > self::MAX_INCIDENTS ) {
			$out          = array_slice( $out, 0, self::MAX_INCIDENTS );
			self::$capped = true;
		}

		// Marca las incidencias históricas: si el archivo señalado se modificó
		// DESPUÉS de la última vez que el error apareció en el registro, esas
		// líneas son historia, no un fallo vivo. Sin esta marca el usuario
		// intenta reparar algo ya corregido y parece que el motor no funciona.
		foreach ( $out as $i => $inc ) {
			$out[ $i ]['stale'] = false;
			if ( empty( $inc['file'] ) || empty( $inc['last_unix'] ) ) {
				continue;
			}
			$mtime = @filemtime( $inc['file'] );
			if ( $mtime && $mtime > (int) $inc['last_unix'] ) {
				$out[ $i ]['stale'] = true;
			}
		}

		return $out;
	}

	/**
	 * Convierte la marca de tiempo del registro en tiempo Unix.
	 * WordPress escribe el registro en UTC, con formato «25-Jul-2026 08:50:17 UTC».
	 *
	 * @param string $ts Marca de tiempo.
	 * @return int 0 si no se pudo interpretar.
	 */
	public static function ts_to_unix( $ts ) {
		$ts = trim( (string) $ts );
		if ( '' === $ts ) {
			return 0;
		}
		if ( ! preg_match( '/\b(?:UTC|GMT|[+-]\d{2}:?\d{2}|[A-Z]{3,4})\s*$/', $ts ) ) {
			$ts .= ' UTC';
		}
		$unix = strtotime( $ts );
		return $unix ? (int) $unix : 0;
	}

	/**
	 * Registros que existen pero PHP no puede leer. Es un problema de entorno,
	 * no «no hay registro»: hay que decírselo al usuario con claridad.
	 *
	 * @return array
	 */
	public static function unreadable_candidates() {
		$out = array();
		foreach ( self::candidate_paths() as $p ) {
			$trusted = self::resolve_trusted_path( $p );
			if ( $trusted && ! @is_readable( $trusted ) ) {
				$out[] = $trusted;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Qué hay que tocar de verdad en wp-config.php para tener registro.
	 *
	 * Antes el panel imprimía las tres líneas define() siempre, sin mirar si ya
	 * existían. Quien las copiaba tal cual acababa con la constante definida dos
	 * veces, un aviso de PHP en cada petición, y una incidencia bloqueada sin
	 * acción posible — porque wp-config.php no se escribe nunca. Es decir: el
	 * consejo de la herramienta generaba el fallo que la herramienta reportaba.
	 *
	 * Ahora se le pregunta a PHP qué está definido ya. Lo que existe se cambia;
	 * no se vuelve a añadir.
	 *
	 * @return array add, change, ok
	 */
	public static function debug_config_advice() {
		$quiere = array(
			'WP_DEBUG'         => 'true',
			'WP_DEBUG_LOG'     => 'true',
			'WP_DEBUG_DISPLAY' => 'false',
		);
		$add    = array();
		$change = array();

		foreach ( $quiere as $nombre => $deseado ) {
			if ( ! defined( $nombre ) ) {
				$add[ $nombre ] = $deseado;
				continue;
			}
			$valor = constant( $nombre );
			// WP_DEBUG_LOG admite una ruta además de true, y una ruta también
			// activa el registro: en ese caso no hay nada que cambiar.
			$activo = ( true === $valor ) || ( is_string( $valor ) && '' !== $valor );
			$ok     = ( 'true' === $deseado ) ? $activo : ( false === $valor );
			if ( ! $ok ) {
				$change[ $nombre ] = $deseado;
			}
		}

		return array(
			'add'    => $add,
			'change' => $change,
			'ok'     => ( empty( $add ) && empty( $change ) ),
		);
	}

	/**
	 * Quita la coletilla de ruta larga del mensaje.
	 *
	 * @param string $msg Mensaje.
	 * @return string
	 */
	public static function short_message( $msg ) {
		$clean = preg_replace( '/\s+in\s+[^\s\'"]+?\.php(?:\s+on\s+line\s+\d+|:\d+)\s*$/i', '', $msg );
		return '' !== trim( (string) $clean ) ? trim( $clean ) : $msg;
	}

	/**
	 * Escanea el log del sitio.
	 *
	 * @return array incidents, log_path, error
	 */
	public static function scan() {
		$path = self::find_log();
		if ( ! $path ) {
			$bloqueados = self::unreadable_candidates();
			if ( ! empty( $bloqueados ) ) {
				return array(
					'incidents' => array(),
					'log_path'  => '',
					'blocked'   => $bloqueados,
					'truncated' => false,
					'capped'    => false,
					'error'     => sprintf(
						/* translators: %s: ruta del registro. */
						__( 'The log exists at «%s» but PHP does not have permission to read it. Fix it below and reload.', 'ai-bug-hunter' ),
						$bloqueados[0]
					),
				);
			}
			return array(
				'incidents' => array(),
				'log_path'  => '',
				'blocked'   => array(),
				'truncated' => false,
				'capped'    => false,
				'error'     => __( 'No readable error log was found. Enable the log from the Settings tab to start capturing errors.', 'ai-bug-hunter' ),
			);
		}
		$text      = self::tail( $path );
		$incidents = self::parse( $text );

		// Un registro recortado en silencio miente por omisión: el usuario ve
		// una lista corta y da por hecho que no hay nada más. Lo mismo vale para
		// el tope de incidencias: si se cortó, se dice, y se dice qué tope fue.
		$recortado = self::was_trimmed();
		$topado    = self::was_capped();

		$avisos = array();
		if ( $recortado ) {
			$avisos[] = __( 'The error log is too large to read in full, so only its most recent part is listed here. Older entries are not shown. Once you have reviewed what matters, use the "Clear log" button on this page, or the selective cleanup, to shrink it.', 'ai-bug-hunter' );
		}
		if ( $topado ) {
			$avisos[] = sprintf(
				/* translators: %s: número máximo de incidencias listadas. */
				__( 'Only the %s most serious distinct issues are listed on this screen, so that a log flooded with errors cannot make it time out. Clear the log, or use the selective cleanup, to see the rest.', 'ai-bug-hunter' ),
				number_format_i18n( self::MAX_INCIDENTS )
			);
		}

		return array(
			'incidents' => $incidents,
			'log_path'  => $path,
			'blocked'   => array(),
			'truncated' => $recortado,
			'capped'    => $topado,
			'error'     => implode( ' ', $avisos ),
		);
	}

	/**
	 * Busca una incidencia por su clave.
	 *
	 * @param string $key Clave.
	 * @return array|false
	 */
	public static function get_incident( $key ) {
		$scan = self::scan();
		foreach ( $scan['incidents'] as $inc ) {
			if ( $inc['key'] === $key ) {
				return $inc;
			}
		}
		return false;
	}

	/**
	 * Incidencias ocultadas por el usuario: clave => momento en que se ocultó.
	 * Si el error vuelve a aparecer con fecha posterior, reaparece solo.
	 *
	 * @return array
	 */
	public static function dismissed() {
		$d = get_option( 'abh_dismissed', array() );
		return is_array( $d ) ? $d : array();
	}

	/**
	 * Oculta una incidencia.
	 *
	 * @param string $key Clave.
	 * @return void
	 */
	public static function dismiss( $key ) {
		$d = self::dismissed();
		$d[ $key ] = time();
		if ( count( $d ) > 300 ) {
			$d = array_slice( $d, -300, null, true );
		}
		update_option( 'abh_dismissed', $d, false );
	}

	/**
	 * Vuelve a mostrar todas las incidencias ocultas.
	 *
	 * @return void
	 */
	public static function undismiss_all() {
		delete_option( 'abh_dismissed' );
	}

	/**
	 * ¿Está oculta esta incidencia y sin reapariciones posteriores?
	 *
	 * @param array $inc Incidencia.
	 * @return bool
	 */
	public static function is_dismissed( $inc ) {
		$d = self::dismissed();
		$r = self::repaired();
		$k = $inc['key'];
		$mark = 0;
		if ( isset( $d[ $k ] ) ) {
			$mark = (int) $d[ $k ];
		}
		if ( isset( $r[ $k ] ) && (int) $r[ $k ] > $mark ) {
			$mark = (int) $r[ $k ];
		}
		if ( 0 === $mark ) {
			return false;
		}
		$last = isset( $inc['last_unix'] ) ? (int) $inc['last_unix'] : 0;
		// Si volvió a ocurrir después de ocultarla o repararla, se muestra de nuevo.
		return ( 0 === $last || $last <= $mark );
	}

	/**
	 * Incidencias que HUNTER AI reparó, con la marca de tiempo del arreglo.
	 *
	 * @return array clave => timestamp.
	 */
	public static function repaired() {
		$r = get_option( 'abh_repaired', array() );
		return is_array( $r ) ? $r : array();
	}

	/**
	 * Marca una incidencia como reparada.
	 *
	 * El registro de errores es histórico y acumulativo: reparar el código no
	 * borra las líneas antiguas. Sin esta marca, un error ya corregido seguiría
	 * apareciendo como pendiente para siempre. Si el error vuelve a ocurrir
	 * después del arreglo, la incidencia reaparece sola.
	 *
	 * @param string $key Clave de la incidencia.
	 * @return void
	 */
	public static function mark_repaired( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return;
		}
		$r         = self::repaired();
		$r[ $key ] = time();
		if ( count( $r ) > 300 ) {
			$r = array_slice( $r, -300, null, true );
		}
		update_option( 'abh_repaired', $r, false );
	}

	/**
	 * ¿El archivo que el registro acusa de no compilar compila ahora mismo?
	 *
	 * El registro de errores es un histórico: cuando arreglas un archivo, nadie
	 * vuelve atrás a borrar las líneas viejas. Por eso un «syntax error» de hace
	 * tres días sigue apareciendo como pendiente sobre un archivo que ya está
	 * perfecto, y el panel da la impresión de no saber resolverlo.
	 *
	 * Hasta ahora eso solo se descubría lanzando una reparación entera. Es
	 * absurdo: para saber si un archivo compila basta con preguntárselo a PHP.
	 * Sin red, sin descargas, sin tokens, y sin depender de la fecha de
	 * modificación, que engaña en cuanto restauras desde una copia.
	 *
	 * Solo aplica a errores de sintaxis, que son los únicos donde «compila
	 * ahora» demuestra por sí solo que la línea del registro es pasado. Un fallo
	 * en tiempo de ejecución puede seguir ocurriendo en un archivo que compila
	 * perfectamente.
	 *
	 * @param array $inc Incidencia.
	 * @return bool
	 */
	public static function syntax_already_fixed( $inc ) {
		$kind = isset( $inc['kind'] ) ? strtolower( (string) $inc['kind'] ) : '';
		$msg  = isset( $inc['message'] ) ? (string) $inc['message'] : '';

		// Una excepción de tiempo de ejecución cuyo TEXTO dice «Syntax error» no
		// es un error de sintaxis del archivo: JsonException lleva ese mensaje
		// literal y PDO emite «Syntax error at or near». Ese archivo compila, y
		// compilará igual mañana, así que aceptarlo aquí daría por resuelto un
		// fatal que sigue tumbando el sitio en cada carga. La marca inequívoca
		// es «Uncaught»: un Parse error de PHP nunca la lleva.
		if ( preg_match( '/\bUncaught\b/i', $msg ) ) {
			return false;
		}

		// Sólo cuenta la forma real del diagnóstico de PHP. «syntax error» a
		// secas no basta: PHP siempre escribe la coma y el «unexpected».
		$es_sintaxis = ( false !== strpos( $kind, 'parse' ) )
			|| preg_match( '/\bparse error\b/i', $msg )
			|| preg_match( '/syntax error,\s*unexpected/i', $msg )
			|| preg_match( '/unexpected end of file/i', $msg );
		if ( ! $es_sintaxis ) {
			return false;
		}

		$rel = isset( $inc['rel_path'] ) ? (string) $inc['rel_path'] : '';
		if ( '' === $rel || ! class_exists( 'ABH_Guard' ) || ! class_exists( 'ABH_Engine' ) || ! class_exists( 'ABH_Verifier' ) ) {
			return false;
		}

		// LA CONTENCIÓN VA PRIMERO, SIEMPRE. La ruta se resuelve por el guardián
		// —el mismo que usa ABH_Engine::read_file()— y solo la ruta canónica que
		// devuelve sirve de clave del recuerdo. Nada del texto del registro
		// llega a la caché, así que una entrada memorizada no puede saltarse una
		// comprobación: para llegar a ella hay que haberla pasado.
		$real = ABH_Guard::resolve_existing_path( $rel, null );
		if ( false === $real ) {
			return false;
		}

		// Leer y analizar un archivo entero por cada incidencia era la parte
		// cara: quien engorda el registro sin estar autenticado fabricaba miles
		// de avisos distintos que señalaban el mismo puñado de archivos, y la
		// pantalla principal los leía y analizaba uno por uno hasta agotar el
		// tiempo. Un archivo se analiza UNA vez por petición.
		$clave = $real . '|' . (int) @filemtime( $real ) . '|' . (int) @filesize( $real );
		if ( array_key_exists( $clave, self::$lint_cache ) ) {
			return self::$lint_cache[ $clave ];
		}

		$veredicto = false;
		$codigo    = ABH_Engine::read_file( $rel );
		if ( false !== $codigo && '' !== $codigo ) {
			$lint = ABH_Verifier::lint( $codigo );

			// Sin el analizador de PHP no se declara nada. El respaldo heurístico
			// cuenta llaves, y contando llaves un archivo realmente roto pasa por
			// bueno. ABH_Guard hace lo mismo (BH-SEC-024): si la evidencia no está
			// disponible, se falla hacia el lado seguro, que aquí es dejar la
			// incidencia en pendientes.
			if ( isset( $lint['method'] ) && 'token_get_all' === $lint['method'] ) {
				$veredicto = ! empty( $lint['ok'] );
			}
		}

		// El recuerdo también tiene tope: se vacía entero antes que crecer sin
		// límite. Se pierde velocidad, nunca memoria.
		if ( count( self::$lint_cache ) >= self::MAX_LINT_CACHE ) {
			self::$lint_cache = array();
		}
		self::$lint_cache[ $clave ] = $veredicto;

		return $veredicto;
	}

	/**
	 * Incidencias cuyo archivo se comprobó intacto, con la marca de tiempo.
	 *
	 * @return array clave => timestamp.
	 */
	public static function intact() {
		$r = get_option( 'abh_intact', array() );
		return is_array( $r ) ? $r : array();
	}

	/**
	 * Marca una incidencia como «el archivo señalado está intacto».
	 *
	 * Distinto de mark_repaired(): allí HUNTER arregló algo; aquí no había nada
	 * que arreglar. El archivo coincide byte a byte con el original publicado
	 * por su autor y compila. Las líneas del registro describen un estado
	 * anterior: el registro es acumulativo y nadie lo reescribe cuando el
	 * archivo se repara.
	 *
	 * Sin esta marca la comprobación se pierde al cerrar la consola, y la
	 * incidencia vuelve a ofrecer «Reparar con HUNTER AI» sobre un archivo sano
	 * —gastando tokens cada vez que alguien lo intenta—.
	 *
	 * Si el error vuelve a ocurrir después de la marca, la incidencia reaparece
	 * sola: la comparación se hace contra la última fecha del registro.
	 *
	 * @param string $key Clave de la incidencia.
	 * @return void
	 */
	public static function mark_intact( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return;
		}
		$r         = self::intact();
		$r[ $key ] = time();
		if ( count( $r ) > 300 ) {
			$r = array_slice( $r, -300, null, true );
		}
		update_option( 'abh_intact', $r, false );
	}

	/**
	 * ¿Se comprobó que el archivo de esta incidencia estaba intacto, y no ha
	 * vuelto a fallar desde entonces?
	 *
	 * @param array $inc Incidencia.
	 * @return bool
	 */
	public static function is_intact( $inc ) {
		$k = isset( $inc['key'] ) ? (string) $inc['key'] : '';
		if ( '' === $k ) {
			return false;
		}
		$r = self::intact();
		if ( ! isset( $r[ $k ] ) ) {
			return false;
		}
		$mark = (int) $r[ $k ];
		$last = isset( $inc['last_unix'] ) ? (int) $inc['last_unix'] : 0;
		// Si el error volvió a ocurrir después de la comprobación, ya no vale.
		return ( 0 === $last || $last <= $mark );
	}

	/**
	 * Pone un temporal recién creado bajo vigilancia.
	 *
	 * Las salidas ordenadas de la limpieza ya borran el temporal, pero una
	 * petición puede morir en medio: tiempo de ejecución agotado, un fatal, el
	 * proceso reciclado. En ese hueco el temporal sobrevive con TODO el
	 * contenido conservado del registro dentro, y nadie lo recogía. Se apunta
	 * aquí y un cierre de emergencia lo borra pase lo que pase.
	 *
	 * Se guarda además la firma del archivo (dispositivo e inodo) para no
	 * borrar por el nombre: tras el renombrado ese nombre queda libre y otra
	 * petición podría estar usándolo ya para SU temporal.
	 *
	 * @param string   $tmp_path Ruta del temporal.
	 * @param resource $tmp      Flujo abierto sobre él.
	 * @return void
	 */
	private static function guard_temp( $tmp_path, $tmp ) {
		// La ruta se normaliza igual que la que arma el barrido, o el barrido no
		// reconocería como vivo el temporal de esta misma petición.
		$tmp_path = wp_normalize_path( (string) $tmp_path );
		if ( '' === $tmp_path ) {
			return;
		}
		$firma = array( 'dev' => 0, 'ino' => 0 );
		$stat  = @fstat( $tmp );
		if ( is_array( $stat ) ) {
			$firma['dev'] = isset( $stat['dev'] ) ? (int) $stat['dev'] : 0;
			$firma['ino'] = isset( $stat['ino'] ) ? (int) $stat['ino'] : 0;
		}
		self::$temp_guard[ $tmp_path ] = $firma;

		if ( ! self::$temp_hooked ) {
			self::$temp_hooked = true;
			register_shutdown_function( array( __CLASS__, 'shutdown_temp_cleanup' ) );
		}
	}

	/**
	 * Levanta la vigilancia de un temporal del que ya se encargó quien lo creó.
	 *
	 * @param string $tmp_path Ruta del temporal.
	 * @return void
	 */
	private static function release_temp( $tmp_path ) {
		unset( self::$temp_guard[ wp_normalize_path( (string) $tmp_path ) ] );
	}

	/**
	 * Cierre de emergencia: borra los temporales que sigan vivos al terminar.
	 *
	 * Se ejecuta siempre que PHP llegue a apagarse, incluido el fatal por
	 * tiempo agotado, que es el final abrupto habitual de una limpieza larga.
	 * No cubre el caso en que al proceso lo matan de golpe (SIGKILL, corte de
	 * corriente); para eso está el barrido de huérfanos, que recoge lo que este
	 * cierre no pudo.
	 *
	 * Público solo porque register_shutdown_function necesita poder llamarlo.
	 *
	 * @return void
	 */
	public static function shutdown_temp_cleanup() {
		$pendientes       = self::$temp_guard;
		self::$temp_guard = array();

		foreach ( $pendientes as $tmp_path => $firma ) {
			if ( '' === $tmp_path ) {
				continue;
			}
			clearstatcache( true, $tmp_path );
			// Un enlace simbólico nunca es nuestro temporal; ni se toca.
			if ( is_link( $tmp_path ) || ! is_file( $tmp_path ) ) {
				continue;
			}
			// Si el nombre ya apunta a otro archivo —el renombrado lo dejó
			// libre y otra petición lo tomó— no es el nuestro y no se borra.
			if ( $firma['ino'] > 0 ) {
				$ahora = @stat( $tmp_path );
				if ( ! is_array( $ahora ) || ! isset( $ahora['ino'] ) || ! isset( $ahora['dev'] ) ) {
					continue;
				}
				if ( (int) $ahora['ino'] !== $firma['ino'] || (int) $ahora['dev'] !== $firma['dev'] ) {
					continue;
				}
			}
			@unlink( $tmp_path );
		}
	}

	/**
	 * Recoge los temporales que dejaron ejecuciones ANTERIORES interrumpidas.
	 *
	 * El cierre de emergencia sirve para la petición en curso, pero lo que ya
	 * quedó tirado en disco antes de esta versión —o tras un proceso matado sin
	 * aviso— no se limpia solo, y cada resto puede pesar tanto como el registro
	 * conservado. Este barrido es deliberadamente estrecho: solo borra lo que
	 * este plugin creó de forma demostrable.
	 *
	 * Cuatro condiciones, todas obligatorias:
	 *  - el nombre casa con el patrón EXACTO que produce tempnam() con nuestro
	 *    prefijo —prefijo más el sufijo aleatorio que añade el sistema—, no con
	 *    un simple «empieza por»;
	 *  - el archivo vive en la carpeta del registro de confianza, comprobado
	 *    contra la ruta canónica de esa carpeta, no contra el texto de la ruta;
	 *  - no es un enlace simbólico —se comprueba antes de tocarlo, y unlink()
	 *    además borra el enlace y jamás su destino, así que ni siquiera un
	 *    cambio a mitad de camino puede destruir un archivo ajeno—;
	 *  - lleva quieto más de TEMP_MAX_AGE, de modo que el temporal de una
	 *    limpieza que esté corriendo ahora mismo en otra petición es intocable.
	 *
	 * @param string $log_path Registro ya localizado, si quien llama lo tiene.
	 *                         Se vuelve a validar igual: venga de donde venga,
	 *                         solo se barre la carpeta de un registro de
	 *                         confianza.
	 * @return int Cuántos huérfanos se borraron.
	 */
	public static function sweep_orphan_temp( $log_path = '' ) {
		$log_path = (string) $log_path;
		$path     = '' !== $log_path ? $log_path : self::find_log();
		$path     = $path ? self::resolve_trusted_path( $path ) : false;
		if ( ! $path ) {
			return 0;
		}
		$dir = realpath( dirname( $path ) );
		if ( false === $dir ) {
			return 0;
		}
		$dir = rtrim( wp_normalize_path( $dir ), '/' );
		if ( '' === $dir ) {
			return 0;
		}

		$entradas = @scandir( $dir );
		if ( ! is_array( $entradas ) ) {
			return 0;
		}

		// tempnam() añade al prefijo un sufijo aleatorio corto de letras y
		// cifras. En Windows el nombre sale de otra forma y no casa: allí el
		// huérfano se queda, pero allí tampoco hay procesos reciclados a mitad
		// de una limpieza, y el cierre de emergencia sigue cubriéndolo.
		$patron   = '/^' . preg_quote( self::TEMP_PREFIX, '/' ) . '[A-Za-z0-9]{1,32}$/';
		$ahora    = time();
		$borrados = 0;

		foreach ( $entradas as $nombre ) {
			if ( '.' === $nombre || '..' === $nombre || ! preg_match( $patron, $nombre ) ) {
				continue;
			}
			$candidato = $dir . '/' . $nombre;
			// Un temporal de ESTA petición está vivo aunque parezca antiguo.
			if ( isset( self::$temp_guard[ $candidato ] ) ) {
				continue;
			}
			clearstatcache( true, $candidato );
			if ( is_link( $candidato ) || ! is_file( $candidato ) ) {
				continue;
			}
			// La carpeta tiene que ser la esperada también después de resolver
			// la ruta: nada de travesías ni de rutas que apunten a otro sitio.
			$real = realpath( $candidato );
			if ( false === $real ) {
				continue;
			}
			$real = wp_normalize_path( $real );
			if ( ! hash_equals( $dir . '/' . $nombre, $real ) ) {
				continue;
			}
			$tocado = @filemtime( $candidato );
			if ( false === $tocado || ( $ahora - (int) $tocado ) <= self::TEMP_MAX_AGE ) {
				continue;
			}
			if ( @unlink( $candidato ) ) {
				++$borrados;
			}
		}

		return $borrados;
	}

	/**
	 * Elimina del registro SOLO las líneas de errores ya resueltos.
	 *
	 * Alternativa a vaciar el registro completo, que también borraría errores
	 * todavía sin revisar. Conserva cualquier entrada que no esté resuelta y
	 * cualquier reaparición posterior al arreglo. Devuelve el detalle de lo
	 * que se quitó para que la operación sea auditable.
	 *
	 * ESTA ES LA ÚNICA RUTA DESTRUCTIVA DEL PLUGIN QUE NO TIENE COPIA PREVIA, y
	 * el registro puede estar compartido con otros programas del servidor. Por
	 * eso el original NO SE TOCA hasta el final: el reemplazo se construye
	 * entero en un archivo temporal, se mide byte a byte, se relee para
	 * comprobar que su huella coincide con lo que se escribió, y solo entonces
	 * se cambia de sitio con un renombrado, que el sistema de archivos hace de
	 * una pieza. O queda el registro de antes completo, o queda el reemplazo
	 * verificado; nunca un archivo a medias.
	 *
	 * Antes se truncaba PRIMERO y se reescribía después, sin comprobar ni una
	 * sola escritura: a partir del truncado, cualquier fallo dejaba el registro
	 * destruido —incluidas las líneas de otras aplicaciones— y el recuento que
	 * se anunciaba era el que se pretendía escribir, no el que quedó en disco.
	 *
	 * @param bool $dry_run Solo contar, sin escribir.
	 * @return array
	 */
	public static function purge_resolved( $dry_run = false ) {
		// Misma resolución de ruta de confianza que usa el vaciado completo.
		$path = self::find_log();
		$path = $path ? self::resolve_trusted_path( $path ) : false;
		if ( ! $path || ! is_readable( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'I cannot find the error log.', 'ai-bug-hunter' ) );
		}
		if ( ! $dry_run && ! is_writable( $path ) ) {
			return array( 'ok' => false, 'message' => __( 'The log does not have write permissions.', 'ai-bug-hunter' ) );
		}
		clearstatcache( true, $path );
		if ( (int) @filesize( $path ) <= 0 ) {
			return array( 'ok' => false, 'message' => __( 'The log is already empty.', 'ai-bug-hunter' ) );
		}

		// Antes de crear un temporal nuevo, se recogen los que dejaron
		// ejecuciones anteriores interrumpidas. Va aquí y no en la carga de la
		// pantalla porque esto es una acción que pide el operador: el barrido
		// no le cuesta un recorrido de carpeta a cada visita del panel. Se hace
		// fuera del cerrojo, que todavía no se ha tomado.
		if ( ! $dry_run ) {
			self::sweep_orphan_temp( $path );
		}

		$marks = array();
		foreach ( self::dismissed() as $k => $ts ) {
			$marks[ $k ] = (int) $ts;
		}
		foreach ( self::repaired() as $k => $ts ) {
			if ( ! isset( $marks[ $k ] ) || (int) $ts > $marks[ $k ] ) {
				$marks[ $k ] = (int) $ts;
			}
		}
		if ( empty( $marks ) ) {
			return array( 'ok' => false, 'message' => __( 'No errors have been marked as resolved yet, so there is nothing to clear.', 'ai-bug-hunter' ) );
		}

		$rx_line = '/^\[(?P<ts>[^\]]+)\]\s+(?:PHP\s+)?(?P<kind>Parse error|Fatal error|Recoverable fatal error|Warning|Notice|Deprecated)\s*:\s*(?P<msg>.*)$/i';

		// El registro se abre UNA vez y todo —leer, construir el reemplazo y
		// cambiarlo de sitio— ocurre bajo el mismo cerrojo exclusivo, igual que
		// hace clear(). Antes se leía entero a memoria, se soltaba, y se
		// reescribía después: todo error registrado en ese hueco desaparecía sin
		// dejar rastro. Además se recorre en flujo, a trozos, para que la memoria
		// del proceso no crezca con el tamaño del registro.
		$fh = @fopen( $path, $dry_run ? 'rb' : 'c+b' );
		if ( false === $fh ) {
			return array( 'ok' => false, 'message' => __( 'The log could not be opened for the cleanup.', 'ai-bug-hunter' ) );
		}
		$locked = @flock( $fh, $dry_run ? LOCK_SH : LOCK_EX );
		if ( ! $locked ) {
			@fclose( $fh );
			return array( 'ok' => false, 'message' => __( 'The log is in use right now, so it was left untouched. Try the cleanup again in a moment.', 'ai-bug-hunter' ) );
		}

		// Lo que se conserva se construye en un archivo temporal DENTRO de la
		// misma carpeta del registro. Tiene que ser esa carpeta y no la temporal
		// del sistema: el cambio final es un renombrado, y un renombrado solo es
		// de una pieza dentro del mismo sistema de archivos. tempnam() le da
		// nombre impredecible y permisos 0600, que importa porque mientras
		// existe contiene el registro y esa carpeta puede estar publicada.
		$tmp      = null;
		$tmp_path = '';
		if ( ! $dry_run ) {
			$dir      = wp_normalize_path( dirname( $path ) );
			// El prefijo sale de la constante: el barrido de huérfanos reconoce
			// los temporales por él, y si aquí se escribiera otro a mano dejaría
			// de encontrarlos.
			$tmp_path = @tempnam( $dir, self::TEMP_PREFIX );
			if ( ! is_string( $tmp_path ) || '' === $tmp_path || wp_normalize_path( dirname( $tmp_path ) ) !== $dir ) {
				// tempnam() se va a la carpeta temporal del sistema cuando la
				// del registro no admite escritura. Desde allí el cambio dejaría
				// de ser de una pieza, así que se prefiere no tocar nada.
				if ( is_string( $tmp_path ) && '' !== $tmp_path ) {
					@unlink( $tmp_path );
				}
				@flock( $fh, LOCK_UN );
				@fclose( $fh );
				return array( 'ok' => false, 'message' => __( 'The folder that holds the log does not allow creating the temporary file needed to rewrite it safely, so the log was left untouched.', 'ai-bug-hunter' ) );
			}
			$tmp = @fopen( $tmp_path, 'w+b' );
			if ( false === $tmp ) {
				@unlink( $tmp_path );
				@flock( $fh, LOCK_UN );
				@fclose( $fh );
				return array( 'ok' => false, 'message' => __( 'There is no temporary space available to rewrite the log safely, so nothing was changed.', 'ai-bug-hunter' ) );
			}
			// Desde este punto el temporal existe y puede pesar tanto como todo
			// lo que se conserve del registro. Queda vigilado: si la petición
			// muere aquí en medio —tiempo agotado, fatal, proceso reciclado— el
			// cierre de emergencia lo borra igual. Las salidas ordenadas de
			// abajo siguen borrándolo ellas mismas y levantan la vigilancia.
			self::guard_temp( $tmp_path, $tmp );
		}

		// Salida única para todo lo que falle: se cierra, se borra el temporal y
		// el registro se queda exactamente como estaba.
		$abortar = function ( $mensaje ) use ( $fh, $tmp, $tmp_path ) {
			if ( null !== $tmp ) {
				@fclose( $tmp );
			}
			if ( '' !== $tmp_path ) {
				@unlink( $tmp_path );
				self::release_temp( $tmp_path );
			}
			@flock( $fh, LOCK_UN );
			@fclose( $fh );
			return array( 'ok' => false, 'message' => $mensaje );
		};

		$removed = 0;
		$kept    = 0;
		$bytes   = 0;
		$claves  = array();
		$huella  = hash_init( 'crc32b' );
		$current = array( 'key' => '', 'ts' => 0, 'text' => '', 'contado' => false );

		// Vuelca un bloque al temporal. Los bytes y la huella se acumulan de lo
		// que se ESCRIBIÓ, y el bloque se marca como contado: el recuento que
		// verá el operador sale de aquí, nunca de lo que se pretendía hacer.
		$volcar = function ( &$bloque ) use ( $tmp, $huella, &$kept, &$bytes ) {
			$texto          = $bloque['text'];
			$bloque['text'] = '';
			if ( null !== $tmp && '' !== $texto ) {
				if ( ! self::write_all( $tmp, $texto ) ) {
					return false;
				}
				hash_update( $huella, $texto );
				$bytes += strlen( $texto );
			}
			if ( ! $bloque['contado'] ) {
				$bloque['contado'] = true;
				++$kept;
			}
			return true;
		};

		$cerrar = function ( &$bloque ) use ( $marks, $volcar, &$removed, &$claves ) {
			if ( '' === $bloque['text'] && ! $bloque['contado'] ) {
				return true;
			}
			$k = $bloque['key'];
			// Solo se borra lo que se puede atribuir SIN DUDA a un error de este
			// plugin ya dado por resuelto. Se conserva todo lo que no esté
			// resuelto, y también cualquier reaparición posterior al arreglo
			// (esa sí es un fallo vivo). Un bloque del que ya se volcó una parte
			// tampoco se borra: lo escrito manda sobre la intención.
			if ( ! $bloque['contado'] && '' !== $k && isset( $marks[ $k ] ) && $bloque['ts'] > 0 && $bloque['ts'] <= $marks[ $k ] ) {
				++$removed;
				$claves[ $k ]      = true;
				$bloque['text']    = '';
				$bloque['contado'] = true;
				return true;
			}
			return $volcar( $bloque );
		};

		rewind( $fh );
		$entero  = true;
		$parcial = false;
		while ( false !== ( $raw = fgets( $fh, self::READ_CHUNK ) ) ) {
			// fgets() sin tope lee hasta el salto de línea, así que una sola
			// línea sin saltos se traería el registro entero a memoria. Se lee
			// por trozos: el trozo que no termina en salto es la MISMA línea
			// física y sigue perteneciendo al bloque en curso.
			$continua = $parcial;
			$parcial  = ( "\n" !== substr( $raw, -1 ) );

			if ( $continua ) {
				$current['text'] .= $raw;
			} else {
				$linea = rtrim( $raw, "\r\n" );
				// Exactamente el mismo tratamiento que parse(): recortada igual y
				// medida igual, o las claves no coincidirían y esta limpieza no
				// reconocería lo que el panel ya dio por resuelto.
				$corta = self::clip_line( trim( $linea ) );
				if ( preg_match( $rx_line, $corta, $m ) ) {
					if ( ! $cerrar( $current ) ) {
						$entero = false;
						break;
					}
					$msg     = trim( $m['msg'] );
					$loc     = self::locate( $msg );
					$current = array(
						'key'     => self::incident_key( trim( $m['kind'] ), $loc['rel'], $loc['line'], $msg ),
						'ts'      => self::ts_to_unix( trim( $m['ts'] ) ),
						'text'    => $raw,
						'contado' => false,
					);
					continue;
				}
				// Este registro puede ser compartido con otros programas. Una línea
				// que no continúa una traza de PHP no es nuestra, así que se cierra
				// el bloque en curso —tenga clave o no— y pasa a un bloque sin
				// clave, que no se borra nunca. La condición exigía antes que el
				// bloque en curso TUVIERA clave, y como el bloque sin clave no la
				// tiene, se comparaba contra sí misma: en cuanto se entraba en uno
				// sin clave ya no se cerraba ninguno más y todo lo ajeno se
				// amontonaba en un único bloque que acababa siendo el registro
				// entero en memoria.
				if ( ! self::is_trace_continuation( $linea ) ) {
					if ( ! $cerrar( $current ) ) {
						$entero = false;
						break;
					}
					$current = array( 'key' => '', 'ts' => 0, 'text' => '', 'contado' => false );
				}
				$current['text'] .= $raw;
			}

			// Tope duro por bloque: una traza absurdamente larga se vuelca en vez
			// de acumularse. Volcada ya no se puede borrar, y eso es justo lo que
			// se quiere cuando hay duda: conservar.
			if ( strlen( $current['text'] ) >= self::MAX_BLOCK_BYTES && ! $volcar( $current ) ) {
				$entero = false;
				break;
			}
		}

		if ( $entero && ! $cerrar( $current ) ) {
			$entero = false;
		}

		// Rescate: si alguien escribió mientras leíamos —el registro de PHP no
		// respeta cerrojos—, esas líneas se conservan tal cual en vez de
		// perderse en el cambio.
		if ( $entero ) {
			$current = array( 'key' => '', 'ts' => 0, 'text' => '', 'contado' => false );
			$fin     = ftell( $fh );
			if ( false !== $fin && 0 === fseek( $fh, $fin, SEEK_SET ) ) {
				while ( false !== ( $raw = fgets( $fh, self::READ_CHUNK ) ) ) {
					$current['text'] .= $raw;
					if ( strlen( $current['text'] ) >= self::MAX_BLOCK_BYTES && ! $volcar( $current ) ) {
						$entero = false;
						break;
					}
				}
				if ( $entero && ! $cerrar( $current ) ) {
					$entero = false;
				}
			}
		}

		if ( ! $entero ) {
			return $abortar( __( 'The cleaned log could not be written in full, so nothing was replaced and the log was left exactly as it was. Check the free disk space on the server.', 'ai-bug-hunter' ) );
		}

		if ( 0 === $removed ) {
			return $abortar( __( 'I did not find lines for already resolved errors in the log.', 'ai-bug-hunter' ) );
		}

		if ( $dry_run ) {
			@flock( $fh, LOCK_UN );
			@fclose( $fh );
			return array( 'ok' => true, 'removed' => $removed, 'kept' => $kept, 'dry_run' => true );
		}

		// El original sigue intacto en este punto. Antes de tocarlo, el
		// reemplazo tiene que medir exactamente los bytes que se le escribieron
		// y devolver la misma huella al releerlo entero.
		$verificado = (bool) @fflush( $tmp );
		if ( $verificado ) {
			$stat       = fstat( $tmp );
			$verificado = is_array( $stat ) && isset( $stat['size'] ) && (int) $stat['size'] === $bytes;
		}
		if ( $verificado && 0 === fseek( $tmp, 0, SEEK_SET ) ) {
			$relectura = hash_init( 'crc32b' );
			$leidos    = 0;
			while ( ! feof( $tmp ) ) {
				$trozo = fread( $tmp, self::READ_CHUNK );
				if ( false === $trozo || '' === $trozo ) {
					break;
				}
				$leidos += strlen( $trozo );
				hash_update( $relectura, $trozo );
			}
			$verificado = ( $leidos === $bytes ) && hash_equals( hash_final( $huella ), hash_final( $relectura ) );
		} else {
			$verificado = false;
		}

		if ( ! $verificado ) {
			return $abortar( __( 'The cleaned log did not match what was read from it, so nothing was replaced and the log was left exactly as it was.', 'ai-bug-hunter' ) );
		}

		// Los permisos del original se conservan: el temporal nace en 0600 y el
		// registro puede tener que seguir escribiéndolo otro proceso.
		//
		// DOS LÍMITES DE ESTE DISEÑO, apuntados aquí para que no se redescubran
		// como si fueran fallos:
		//
		// 1. El renombrado cambia el INODO del registro. Un escritor externo de
		//    vida larga —PHP-FPM con su descriptor abierto, un agente de
		//    registros— sigue escribiendo en el inodo viejo, que ya no tiene
		//    nombre, y sus líneas se pierden hasta que reabra el archivo. Es el
		//    precio de que el cambio sea de una pieza: la alternativa, truncar y
		//    reescribir sobre el mismo inodo, deja el registro destruido en
		//    cuanto algo falla a mitad, que es exactamente lo que pasaba antes.
		//    Se prefiere perder unas líneas de un escritor externo a perder el
		//    registro entero, incluido el de otras aplicaciones.
		// 2. Los permisos se copian aquí, pero el PROPIETARIO no se puede
		//    copiar: chown() exige privilegios que PHP no tiene en un hosting
		//    normal. Si el registro lo creó otro usuario del sistema, el
		//    reemplazo queda a nombre del usuario de PHP. Donde eso importe, el
		//    camino es un registro propio del sitio fijado con
		//    ABH_TRUSTED_LOG_PATH, no compartir el registro global de PHP.
		$modo = @fileperms( $path );
		if ( false !== $modo ) {
			@chmod( $tmp_path, $modo & 0777 );
		}
		@fclose( $tmp );

		$cambiado = @rename( $tmp_path, $path );
		@flock( $fh, LOCK_UN );
		@fclose( $fh );
		if ( ! $cambiado ) {
			@unlink( $tmp_path );
			self::release_temp( $tmp_path );
			return array( 'ok' => false, 'message' => __( 'The cleaned log could not replace the original, so the log was left exactly as it was. Check the permissions of the folder that holds it.', 'ai-bug-hunter' ) );
		}
		// Con el renombrado hecho, ese nombre ya no es nuestro temporal: se
		// levanta la vigilancia. Aunque no se levantara, el cierre de emergencia
		// compara el inodo antes de borrar nada, así que jamás se llevaría por
		// delante el temporal que otra petición hubiera creado entretanto con el
		// nombre liberado.
		self::release_temp( $tmp_path );
		clearstatcache( true, $path );

		return array(
			'ok'      => true,
			'removed' => $removed,
			'kept'    => $kept,
			'bytes'   => $bytes,
			'keys'    => count( $claves ),
			'message' => sprintf(
				/* translators: 1: entradas quitadas, 2: entradas conservadas. */
				__( 'Selective cleanup complete: I removed %1$d entries for errors already resolved and kept %2$d that are still unreviewed.', 'ai-bug-hunter' ),
				$removed,
				$kept
			),
		);
	}

	/**
	 * Escribe un texto ENTERO en un flujo, comprobando cada escritura.
	 *
	 * fwrite() puede colocar menos bytes de los que se le piden y decir cuántos
	 * colocó. Quedarse con el primer intento y descartar lo que devuelve pierde
	 * el resto en silencio, que es como un bloque del registro se quedaba a
	 * medias sin que nadie se enterara. Aquí se repite hasta el último byte y se
	 * falla en cuanto una escritura no avanza.
	 *
	 * @param resource $fh    Flujo abierto para escritura.
	 * @param string   $texto Texto a escribir.
	 * @return bool
	 */
	private static function write_all( $fh, $texto ) {
		$largo   = strlen( $texto );
		$escrito = 0;
		while ( $escrito < $largo ) {
			// El caso normal es una sola vuelta: no se copia el texto para nada.
			$n = @fwrite( $fh, 0 === $escrito ? $texto : substr( $texto, $escrito ) );
			if ( false === $n || $n <= 0 ) {
				return false;
			}
			$escrito += (int) $n;
		}
		return true;
	}

	/**
	 * ¿Esta línea continúa la traza de un error de PHP?
	 *
	 * Es la frontera entre lo nuestro y lo de los demás: solo lo que continúa
	 * una traza se considera parte del error anterior y puede irse con él.
	 *
	 * @param string $linea Línea sin el salto final.
	 * @return bool
	 */
	private static function is_trace_continuation( $linea ) {
		$linea = (string) $linea;
		if ( '' === trim( $linea ) ) {
			return true;
		}
		if ( preg_match( '/^\s/', $linea ) ) {
			return true;
		}
		return (bool) preg_match( '/^(?:PHP\s+)?(?:Stack trace:|#\d+\s|\d+\.\s|\{main\}|thrown\s+in\s)/i', $linea );
	}

	/**
	 * Vacía el registro de errores.
	 *
	 * @return bool
	 */
	public static function clear() {
		$path = self::find_log();
		$path = $path ? self::resolve_trusted_path( $path ) : false;
		if ( ! $path || ! is_writable( $path ) ) {
			return false;
		}
		// Segunda ocasión para recoger temporales huérfanos: vaciar el registro
		// es la otra tarea de mantenimiento que pide el operador a mano, y quien
		// llega aquí es justamente quien está intentando recuperar espacio.
		self::sweep_orphan_temp( $path );
		$fh = @fopen( $path, 'c+b' );
		if ( false === $fh ) {
			return false;
		}
		$locked = @flock( $fh, LOCK_EX );
		$ok     = $locked && @ftruncate( $fh, 0 ) && @fflush( $fh );
		if ( $locked ) {
			@flock( $fh, LOCK_UN );
		}
		@fclose( $fh );
		return (bool) $ok;
	}
}
