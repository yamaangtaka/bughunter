<?php
/**
 * PUENTE CON THOTH SECURITY SYSTEMS.
 *
 * Bug Hunter lee el registro de errores de PHP. Hay toda una familia de
 * problemas que nunca llega ahí: cuando alguien pide directamente un archivo
 * .php de un plugin, WordPress no llega a arrancar, así que tampoco llega a
 * configurar el registro. El error se pierde. Thoth sí ve esas peticiones,
 * porque vive en la capa de la petición, no en la del error.
 *
 * Este puente une las dos mitades: Thoth detecta y contiene, Bug Hunter repara.
 *
 * Es de un solo sentido y sin acoplamiento: se usa únicamente la API pública de
 * Thoth y no se modifica nada suyo. Si Thoth no está instalado, Bug Hunter
 * funciona exactamente igual que antes.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Resuelve rutas y decide qué es alcanzable dentro del sitio.
 *
 * POR QUE EXISTE:  El alcance amplio es la función del producto, no un descuido.
 *
 * SI LO RECORTAS:  Cualquier cambio aquí toca el alcance. Antes de tocarlo, mira si estás recortando poder de reparación en nombre de una seguridad que ya está cubierta en otro sitio.
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
 * Class ABH_Bridge
 */
class ABH_Bridge {

	/**
	 * Tope de eventos que UNA petición llega a mirar.
	 *
	 * El registro de Thoth lo llena quien ataca, no quien administra: basta
	 * insistir contra el mismo .php para que crezca sin límite. Sin tope, la
	 * pantalla principal hereda ese tamaño y se muere por tiempo.
	 */
	const MAX_EVENTS = 250;

	/**
	 * Tope de archivos DISTINTOS que se leen del disco en una petición.
	 */
	const MAX_FILES = 50;

	/**
	 * Lectura ya resuelta por ruta ABSOLUTA validada, para esta petición.
	 *
	 * La clave es la ruta que devuelve ABH_Engine::abs_path() DESPUÉS de que
	 * ABH_Guard::check_path() haya dado permiso. Nunca la ruta que llegó en el
	 * evento: la caché no puede servir de atajo para saltarse la comprobación
	 * de contención, porque no se la consulta hasta haberla pasado.
	 *
	 * @var array
	 */
	private static $cache_archivos = array();

	/**
	 * Aviso pendiente cuando una petición se quedó a medias por los topes.
	 *
	 * @var string
	 */
	private static $aviso_tope = '';

	/**
	 * ¿Ya se colgó el aviso del pie de esta pantalla?
	 *
	 * @var bool
	 */
	private static $aviso_colgado = false;

	/**
	 * Texto para la pantalla cuando findings() no pudo mirarlo todo.
	 *
	 * Vacío mientras no se haya alcanzado ningún tope. Se consulta DESPUÉS de
	 * llamar a findings(); truncar en silencio sería peor que no truncar.
	 *
	 * @return string
	 */
	public static function limit_notice() {
		return self::$aviso_tope;
	}

	/**
	 * Cuelga el aviso de tope de la propia pantalla del administrador.
	 *
	 * findings() se llama cuando la página YA se está pintando, así que
	 * admin_notices pasó hace rato: el pie es el enganche que queda por
	 * delante. Se registra una sola vez por petición.
	 *
	 * @return void
	 */
	private static function anunciar_tope() {
		if ( '' === self::$aviso_tope || self::$aviso_colgado ) {
			return;
		}
		if ( ! is_admin() || ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) ) {
			return;
		}
		self::$aviso_colgado = true;
		add_action( 'admin_footer', array( __CLASS__, 'render_limit_notice' ) );
	}

	/**
	 * Pinta el aviso de tope. Enganchado desde anunciar_tope().
	 *
	 * @return void
	 */
	public static function render_limit_notice() {
		$texto = self::limit_notice();
		if ( '' === $texto ) {
			return;
		}
		echo '<div class="notice notice-warning abh-bridge-limit"><p>' . esc_html( $texto ) . '</p></div>';
	}

	/**
	 * Tipos de evento de Thoth en los que puede haber algo que reparar.
	 *
	 * @return array
	 */
	public static function actionable_types() {
		return array(
			'sensitive_path_probe',
			'server_level_block_page',
			'strict_mode_probe',
		);
	}

	/**
	 * ¿Está Thoth instalado y activo?
	 *
	 * @return bool
	 */
	public static function available() {
		return defined( 'THOTH_SECURITY_VERSION' )
			&& class_exists( 'VibeCoder_Core' )
			&& method_exists( 'VibeCoder_Core', 'recent_events' );
	}

	/**
	 * Versión de Thoth, si está.
	 *
	 * @return string
	 */
	public static function version() {
		return defined( 'THOTH_SECURITY_VERSION' ) ? (string) THOTH_SECURITY_VERSION : '';
	}

	/**
	 * Eventos recientes, tal como los entrega Thoth.
	 *
	 * @param int $limit Máximo de eventos.
	 * @return array
	 */
	public static function recent_events( $limit = 100 ) {
		if ( ! self::available() ) {
			return array();
		}
		$eventos = VibeCoder_Core::recent_events( (int) $limit );
		return is_array( $eventos ) ? $eventos : array();
	}

	/**
	 * Resumen por severidad, para la cabecera.
	 *
	 * @return array
	 */
	public static function counts() {
		if ( ! self::available() || ! method_exists( 'VibeCoder_Core', 'event_counts' ) ) {
			return array();
		}
		$c = VibeCoder_Core::event_counts();
		return is_array( $c ) ? $c : array();
	}

	/**
	 * Extrae de un evento la ruta del sitio contra la que se probó.
	 *
	 * @param object|array $evento Evento de Thoth.
	 * @return string Ruta relativa a la raíz de WordPress, o cadena vacía.
	 */
	public static function target_of( $evento ) {
		$evento = (array) $evento;

		$context = isset( $evento['context'] ) ? $evento['context'] : '';
		if ( is_string( $context ) ) {
			$context = json_decode( $context, true );
		}
		if ( ! is_array( $context ) || empty( $context['uri'] ) ) {
			return '';
		}

		$uri = (string) $context['uri'];
		$uri = explode( '?', $uri, 2 )[0];
		$uri = explode( '#', $uri, 2 )[0];

		// Solo interesan los .php dentro del sitio.
		if ( '.php' !== strtolower( substr( $uri, -4 ) ) ) {
			return '';
		}

		// Se descuenta el subdirectorio de instalación, si lo hay.
		$base = wp_parse_url( home_url(), PHP_URL_PATH );
		if ( is_string( $base ) && '' !== $base && '/' !== $base && 0 === strpos( $uri, $base ) ) {
			$uri = substr( $uri, strlen( $base ) );
		}

		return ABH_Guard::normalize( $uri );
	}

	/**
	 * Hallazgos reparables a partir de lo que Thoth bloqueó.
	 *
	 * Ahora mismo hay uno, y es el que motivó todo esto: archivos .php dentro de
	 * wp-content a los que se puede llegar directamente porque les falta el
	 * guardián de ABSPATH.
	 *
	 * CADA ARCHIVO SE LEE UNA VEZ. Antes se marcaba «visto» solo al final, así
	 * que un archivo ya protegido —o imposible de proteger— se salía por su
	 * `continue` sin dejar rastro y el siguiente evento contra el MISMO archivo
	 * lo volvía a leer entero. Mil eventos contra un archivo eran mil lecturas
	 * completas de disco, y el registro de Thoth lo llena quien ataca: bastaba
	 * insistir para tumbar la pantalla principal sin estar autenticado.
	 *
	 * @param int $limit Eventos a revisar.
	 * @return array
	 */
	public static function findings( $limit = 150 ) {
		if ( ! self::available() ) {
			return array();
		}

		$vistos    = array();
		$hallazgos = array();
		$tipos     = self::actionable_types();
		$mirados   = 0;
		$tope_ev   = false;
		$tope_arch = false;

		foreach ( self::recent_events( $limit ) as $evento ) {
			if ( $mirados >= self::MAX_EVENTS ) {
				$tope_ev = true;
				break;
			}
			++$mirados;

			$e = (array) $evento;

			$tipo = isset( $e['type'] ) ? (string) $e['type'] : '';
			if ( ! in_array( $tipo, $tipos, true ) ) {
				continue;
			}

			$rel = self::target_of( $e );
			// Una ruta ya decidida no se vuelve a decidir, diera hallazgo o no.
			if ( '' === $rel || isset( $vistos[ $rel ] ) ) {
				continue;
			}
			$vistos[ $rel ] = true;

			// Solo lo que Bug Hunter tiene permitido tocar. Esto va SIEMPRE
			// antes de mirar la caché: la contención se comprueba por ruta, no
			// se hereda de otra petición ni de otro evento.
			$permiso = ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() );
			if ( ! $permiso['allowed'] ) {
				continue;
			}

			$abs = ABH_Engine::abs_path( $rel );
			if ( ! $abs || ! @is_readable( $abs ) ) {
				continue;
			}

			if ( array_key_exists( $abs, self::$cache_archivos ) ) {
				$reparable = self::$cache_archivos[ $abs ];
			} else {
				if ( count( self::$cache_archivos ) >= self::MAX_FILES ) {
					$tope_arch = true;
					break;
				}
				$contenido = (string) @file_get_contents( $abs );
				// Ya protegido, o imposible de proteger sin tocar la lógica:
				// en ambos casos no hay nada que reparar, y se recuerda.
				$reparable = ! ABH_Motor::has_abspath_guard( $contenido )
					&& ABH_Motor::can_add_guard( $contenido );

				self::$cache_archivos[ $abs ] = $reparable;
			}

			if ( ! $reparable ) {
				continue;
			}

			$hallazgos[] = array(
				'rel_path'   => $rel,
				'event_type' => $tipo,
				'event_time' => isset( $e['event_time'] ) ? (string) $e['event_time'] : '',
				'severity'   => isset( $e['severity'] ) ? (string) $e['severity'] : 'high',
				'ip'         => isset( $e['ip'] ) ? (string) $e['ip'] : '',
				'message'    => isset( $e['message'] ) ? (string) $e['message'] : '',
			);
		}

		// Truncar en silencio deja al administrador creyendo que ya lo vio
		// todo. Si se llegó a un tope, se dice — y se dice qué tope fue.
		$avisos = array();
		if ( $tope_ev ) {
			$avisos[] = sprintf(
				/* translators: %s: número de eventos revisados. */
				__( 'Only the %s most recent security events were reviewed on this screen, so that a very large log cannot make it time out.', 'ai-bug-hunter' ),
				number_format_i18n( self::MAX_EVENTS )
			);
		}
		if ( $tope_arch ) {
			$avisos[] = sprintf(
				/* translators: %s: número de archivos revisados. */
				__( 'Only %s different files were inspected on this screen, so that a very large log cannot make it time out. Reduce the blocked requests, or review the rest from the security log.', 'ai-bug-hunter' ),
				number_format_i18n( self::MAX_FILES )
			);
		}
		// El aviso es de la PETICIÓN, no de la llamada: si una llamada anterior
		// ya truncó, eso sigue siendo verdad aunque esta no truncara nada.
		if ( ! empty( $avisos ) ) {
			self::$aviso_tope = implode( ' ', $avisos );
			self::anunciar_tope();
		}

		return $hallazgos;
	}
}
