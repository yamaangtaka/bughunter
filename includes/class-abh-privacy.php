<?php
/**
 * Redacción determinista antes de transmitir código o registros a un modelo.
 *
 * Los valores sensibles se sustituyen por marcadores aleatorios y reversibles
 * únicamente en memoria. Para propuestas de código, el motor exige que todos
 * los marcadores regresen intactos antes de restaurar el valor original.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Quita del texto lo que identifica al sitio antes de que salga de la máquina.
 *
 * POR QUE EXISTE:  Es lo último que se interpone entre el código del cliente y una API ajena.
 *
 * SI LO RECORTAS:  Un fallo aquí no se nota: el envío funciona igual, sólo que con datos de más. Cualquier cambio necesita prueba de comportamiento, no revisión a ojo.
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
 * Class ABH_Privacy
 */
class ABH_Privacy {

	/**
	 * Crea el estado de una operación de redacción.
	 *
	 * @return array
	 */
	public static function state() {
		try {
			$rand = bin2hex( random_bytes( 6 ) );
		} catch ( Exception $e ) {
			$rand = substr( wp_hash( microtime( true ) . wp_rand() ), 0, 12 );
		}
		return array(
			'prefix' => 'ABH_REDACTED_' . strtoupper( $rand ) . '_',
			'map'    => array(),
			'values' => array(),
			'count'  => 0,
		);
	}

	/**
	 * Registra un valor y devuelve su marcador.
	 *
	 * @param string $value Valor real.
	 * @param array  $state Estado por referencia.
	 * @return string
	 */
	private static function placeholder( $value, &$state ) {
		$value = (string) $value;
		// Evita volver a redactar un marcador creado en una pasada anterior.
		if ( isset( $state['map'][ $value ] ) ) {
			return $value;
		}
		$key   = hash( 'sha256', $value );
		if ( isset( $state['values'][ $key ] ) ) {
			return $state['values'][ $key ];
		}
		$state['count']++;
		$placeholder = $state['prefix'] . $state['count'] . '__';
		$state['map'][ $placeholder ] = $value;
		$state['values'][ $key ]      = $placeholder;
		return $placeholder;
	}

	/**
	 * Redacta secretos y PII frecuentes.
	 *
	 * @param string $text  Texto.
	 * @param array  $state Estado por referencia.
	 * @return string
	 */
	public static function redact( $text, &$state ) {
		$text = (string) $text;
		if ( ! isset( $state['map'] ) ) {
			$state = self::state();
		}

		// Los delimitadores del prompt también son datos sensibles: si aparecen
		// dentro de un comentario o log no pueden cerrar artificialmente el bloque
		// no confiable. Las rutas raíz del servidor se sustituyen por marcadores
		// reversibles antes de enviar contexto a un proveedor externo.
		$literals = array( 'DATOS_NO_CONFIABLES_INICIO', 'DATOS_NO_CONFIABLES_FIN' );
		foreach ( array( defined( 'ABSPATH' ) ? ABSPATH : '', defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '' ) as $path ) {
			$path = (string) $path;
			if ( strlen( rtrim( $path, '/\\' ) ) >= 4 ) {
				$literals[] = $path;
				$literals[] = rtrim( $path, '/\\' );
				if ( function_exists( 'wp_normalize_path' ) ) {
					$literals[] = wp_normalize_path( $path );
					$literals[] = rtrim( wp_normalize_path( $path ), '/' );
				}
			}
		}
		$literals = array_values( array_unique( array_filter( $literals, 'strlen' ) ) );
		usort( $literals, static function ( $a, $b ) { return strlen( $b ) - strlen( $a ); } );
		foreach ( $literals as $literal ) {
			if ( false !== strpos( $text, $literal ) ) {
				$text = str_replace( $literal, self::placeholder( $literal, $state ), $text );
			}
		}

		// Las formas de credencial viven en credential_patterns(): una sola
		// lista para redactar y para detectar un secreto guardado en un campo
		// público. Duplicarla aquí fue exactamente el fallo de alpha80.
		$patterns = array_merge(
			self::credential_patterns(),
			array(
				// Direcciones de correo.
				'/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i',
				// Direcciones IPv4 visibles en registros.
				'/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/',
				// IPv6 en forma completa. Se exigen los ocho grupos: así no hay
				// ninguna otra cosa con la que pueda confundirse.
				'/\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/',
				// IPv6 comprimida. La marca es el «::» literal, que ninguna hora
				// de un registro trae. Sin esa exigencia, «12:34:56» se redactaba
				// como si fuera una dirección y el registro salía ilegible. Los
				// bordes excluyen letra, dígito, punto y guion bajo para que
				// `Clase::metodo()` del código analizado nunca entre aquí.
				'/(?<![0-9A-Za-z_:.])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![0-9A-Za-z_:.])/',
			)
		);

		foreach ( $patterns as $rx ) {
			$text = preg_replace_callback(
				$rx,
				function ( $m ) use ( &$state ) {
					return ABH_Privacy::placeholder( $m[0], $state );
				},
				$text
			);
		}

		// Asignaciones habituales: $api_key = '...', 'password' => '...', "token":"...".
		$assignments = array(
			'/((?:\$)?(?:api[_-]?key|secret|token|password|passwd|pwd|db_password|db_user|db_name|db_host|auth_key|secure_auth_key|logged_in_key|nonce_key)\s*=\s*[\'\"])([^\'\"\r\n]{4,})([\'\"])/i',
			'/([\'\"](?:api[_-]?key|secret|token|password|passwd|pwd|db_password|db_user|db_name|db_host|auth_key|secure_auth_key|logged_in_key|nonce_key)[\'\"]\s*=>\s*[\'\"])([^\'\"\r\n]{4,})([\'\"])/i',
			'/([\'\"](?:api[_-]?key|secret|token|password|passwd|pwd|db_password|db_user|db_name|db_host)[\'\"]\s*:\s*[\'\"])([^\'\"\r\n]{4,})([\'\"])/i',
		);
		foreach ( $assignments as $rx ) {
			$text = preg_replace_callback(
				$rx,
				function ( $m ) use ( &$state ) {
					return $m[1] . ABH_Privacy::placeholder( $m[2], $state ) . $m[3];
				},
				$text
			);
		}

		// Constantes sensibles de WordPress.
		$text = preg_replace_callback(
			'/((?:define\s*\(\s*)[\'\"](?:DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[\'\"]\s*,\s*[\'\"])([^\'\"\r\n]{4,})([\'\"]\s*\))/i',
			function ( $m ) use ( &$state ) {
				return $m[1] . ABH_Privacy::placeholder( $m[2], $state ) . $m[3];
			},
			$text
		);

		// Valores sensibles dentro de consultas URL o formularios serializados.
		$text = preg_replace_callback(
			'/([?&](?:api[_-]?key|token|secret|password|auth)=)([^&\s"\']{4,})/i',
			function ( $m ) use ( &$state ) {
				return $m[1] . ABH_Privacy::placeholder( $m[2], $state );
			},
			$text
		);

		// Credenciales incrustadas en una URL: esquema://usuario:clave@host.
		// Es la forma que más aparece en una cadena de conexión copiada a un
		// registro, y no la reconocía ningún patrón: ni es una asignación ni
		// tiene forma de token. El esquema y el host siguen legibles —hacen
		// falta para entender el error—; quien entra, no.
		$text = preg_replace_callback(
			'#(//)([^/\s:@"\']{1,128}:[^/\s:@"\']{1,128})(@)#',
			function ( $m ) use ( &$state ) {
				return $m[1] . ABH_Privacy::placeholder( $m[2], $state ) . $m[3];
			},
			$text
		);

		return (string) $text;
	}

	/**
	 * Restaura marcadores conocidos. Los desconocidos nunca se interpretan.
	 *
	 * @param string $text  Texto con marcadores.
	 * @param array  $state Estado.
	 * @return string
	 */
	public static function restore( $text, $state ) {
		if ( empty( $state['map'] ) || ! is_array( $state['map'] ) ) {
			return (string) $text;
		}
		return strtr( (string) $text, $state['map'] );
	}

	/**
	 * Vuelve a esconder valores que este estado ya redactó una vez.
	 *
	 * Es la operación inversa de restore(), y hace falta cuando un texto que
	 * salió redactado se restauró para enseñárselo a alguien y después vuelve a
	 * entrar para transmitirse otra vez. Redactar por patrón no basta ahí: un
	 * valor que se reconoció por su contexto —«'password' => '...'»— viaja solo
	 * en la segunda vuelta y ningún patrón lo reconocería. Lo que ya se decidió
	 * que era secreto vuelve a su marcador, con el mismo número.
	 *
	 * @param string $text  Texto ya legible.
	 * @param array  $state Estado de redacción.
	 * @return string
	 */
	public static function rehide( $text, $state ) {
		$text = (string) $text;
		if ( empty( $state['map'] ) || ! is_array( $state['map'] ) ) {
			return $text;
		}
		$inverso = array();
		foreach ( $state['map'] as $marcador => $valor ) {
			$valor = (string) $valor;
			if ( '' !== $valor ) {
				$inverso[ $valor ] = (string) $marcador;
			}
		}
		if ( empty( $inverso ) ) {
			return $text;
		}
		return strtr( $text, $inverso );
	}

	/**
	 * Quita los marcadores que este estado NO creó.
	 *
	 * restore() ya se niega a interpretarlos —solo conoce su propio mapa—, pero
	 * dejarlos en el texto que se enseña tiene su propio coste: el navegador los
	 * guarda y los reenvía en el turno siguiente, y quien lee no distingue un
	 * marcador legítimo de uno que el modelo se inventó. Lo que no es nuestro no
	 * se restaura y tampoco se muestra: se quita.
	 *
	 * @param string $text  Texto devuelto por el modelo.
	 * @param array  $state Estado de redacción.
	 * @return string
	 */
	public static function strip_unknown_placeholders( $text, $state ) {
		$text = (string) $text;
		if ( false === strpos( $text, 'ABH_REDACTED_' ) ) {
			return $text;
		}
		$map = isset( $state['map'] ) && is_array( $state['map'] ) ? $state['map'] : array();
		$out = preg_replace_callback(
			'/ABH_REDACTED_[A-Za-z0-9]*(?:_[0-9]+__)?/',
			function ( $m ) use ( $map ) {
				return isset( $map[ $m[0] ] ) ? $m[0] : '';
			},
			$text
		);
		// Si el motor de expresiones regulares se rindió, no se devuelve el
		// original: se devuelve vacío y quien llama lo trata como respuesta sin
		// contenido. Un fallo aquí no puede acabar restaurando a ciegas.
		return null === $out ? '' : (string) $out;
	}

	/**
	 * Comprueba que el modelo no eliminó, duplicó ni alteró marcadores.
	 *
	 * @param string $before Texto enviado al modelo.
	 * @param string $after  Texto devuelto/reinsertado.
	 * @param array  $state  Estado.
	 * @return bool
	 */
	public static function placeholders_preserved( $before, $after, $state ) {
		if ( empty( $state['map'] ) ) {
			return true;
		}
		foreach ( array_keys( $state['map'] ) as $placeholder ) {
			if ( substr_count( (string) $before, $placeholder ) !== substr_count( (string) $after, $placeholder ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Número de valores redactados.
	 *
	 * @param array $state Estado.
	 * @return int
	 */
	public static function count( $state ) {
		return isset( $state['count'] ) ? (int) $state['count'] : 0;
	}

	/**
	 * Formas conocidas de credencial. Punto único de verdad.
	 *
	 * Se usa para redactar antes de transmitir y para detectar un secreto
	 * guardado por error en un campo que la interfaz muestra en claro.
	 *
	 * No es exhaustiva y no puede serlo: reconoce formatos, no entropía.
	 *
	 * @return array<int,string>
	 */
	public static function credential_patterns() {
		return array(
			// OpenAI, Anthropic y tokens similares de un solo segmento.
			'/\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}\b/',
			// Credenciales de dos segmentos «prefijo:secreto». Esta forma
			// escapaba a la regla anterior: sk-lm-XXXXXXXX:YYYYYYYYYYYY.
			'/\b(?:sk|pk|rk|ak)[-_][A-Za-z0-9_\-]{2,}:[A-Za-z0-9_\-]{8,}/i',
			// Claves de plataformas frecuentes.
			'/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/',
			'/\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/',
			'/\bAIza[A-Za-z0-9_\-]{20,}\b/',
			'/\bhf_[A-Za-z0-9]{20,}\b/',
			'/\br8_[A-Za-z0-9]{20,}\b/',
			// JWT.
			'/\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}\b/',
			// AWS access key IDs.
			'/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/',
			// Bearer tokens escritos en logs o cabeceras.
			'/\bBearer\s+[A-Za-z0-9._~+\/\-=]{12,}\b/i',
			// Bloque de clave privada PEM. Se reconoce el sobre entero porque
			// el cuerpo va partido en líneas: ningún patrón de token lo ve, y
			// una clave privada dentro de un archivo analizado es exactamente
			// lo que no puede salir de la máquina. El cuerpo va acotado y con
			// cuantificador perezoso: no hay repetición anidada que se dispare
			// sobre un registro grande.
			'/-----BEGIN[A-Z ]{0,32}PRIVATE KEY-----[\s\S]{0,8192}?-----END[A-Z ]{0,32}PRIVATE KEY-----/',
		);
	}

	/**
	 * ¿El valor tiene forma de credencial?
	 *
	 * Pensado para campos que la interfaz muestra en claro y que nunca
	 * deberían contener un secreto: el nombre del modelo y la URL base.
	 *
	 * @param mixed $value Valor a comprobar.
	 * @return bool
	 */
	public static function looks_like_secret( $value ) {
		if ( ! is_string( $value ) ) {
			return false;
		}
		$value = trim( $value );
		if ( '' === $value ) {
			return false;
		}
		foreach ( self::credential_patterns() as $rx ) {
			if ( preg_match( $rx, $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Enmascara un valor con forma de credencial para poder mostrarlo.
	 *
	 * Devuelve el valor intacto cuando no parece un secreto: el nombre real
	 * de un modelo debe seguir siendo legible.
	 *
	 * @param mixed $value Valor.
	 * @return string
	 */
	public static function mask_if_secret( $value ) {
		if ( ! is_string( $value ) ) {
			return '';
		}
		if ( ! self::looks_like_secret( $value ) ) {
			return $value;
		}
		return self::mask( $value );
	}

	/**
	 * Enmascarado incondicional: primeros y últimos caracteres.
	 *
	 * @param mixed $value Valor.
	 * @return string
	 */
	public static function mask( $value ) {
		$value = is_string( $value ) ? trim( $value ) : '';
		$len   = strlen( $value );
		if ( $len <= 8 ) {
			return str_repeat( '*', max( 4, $len ) );
		}
		return substr( $value, 0, 3 ) . str_repeat( '*', 8 ) . substr( $value, -3 );
	}
}
