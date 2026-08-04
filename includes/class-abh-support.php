<?php
/**
 * Apoyo al proyecto.
 *
 * La edición WordPress.org permanece gratuita. Esta clase existe para pedir
 * apoyo una sola vez, con números reales en la mano, y para que la
 * petición se pueda apagar para siempre. No cobra, no verifica pagos y no
 * concede permisos: si concediera algo, dejaría de ser apoyo y sería una venta
 * a crédito que nadie puede cobrar.
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ABH_Support
 */
class ABH_Support {

	/**
	 * Estado local: si ya apoyó, cuándo se pospuso la petición y si pidió que
	 * no se le vuelva a preguntar.
	 */
	const OPTION = 'abh_support';

	/**
	 * Cuota anual de apoyo, en dólares. No compra nada. Sostiene el proyecto.
	 */
	const ANUAL_USD = 18;

	/**
	 * Donación mínima sugerida, en dólares.
	 */
	const MINIMO_USD = 5;

	/**
	 * Reparaciones deterministas que tienen que haber ocurrido antes de que el
	 * plugin se atreva a pedir algo. Antes de eso no ha hecho méritos.
	 */
	const UMBRAL_PARA_PEDIR = 3;

	/**
	 * Cada cuánto se vuelve a mostrar el aviso si lo pospusieron.
	 */
	const DESCANSO = 2592000;

	/**
	 * Memoria de proceso para no releer la opción en cada tarjeta.
	 *
	 * @var array|null
	 */
	private static $memo = null;


	/**
	 * Destinos por defecto del proyecto.
	 *
	 * Cada uno se puede sustituir con una constante en wp-config.php, y
	 * cualquiera se puede apagar dejándola vacía: un destino vacío no pinta
	 * botón. Nunca un botón muerto.
	 *
	 * @return array Mapa cual => valor por defecto.
	 */
	public static function defaults() {
		return array(
			'anual'    => 'https://paypal.me/thothmkt',
			'donacion' => 'https://paypal.me/thothmkt',
			'regalo'   => 'ostrovskyemmanuel@gmail.com',
		);
	}


	/**
	 * Constante de wp-config.php que manda sobre cada destino.
	 *
	 * @return array Mapa cual => nombre de constante.
	 */
	public static function constantes() {
		return array(
			'anual'    => 'ABH_SUPPORT_ANNUAL_URL',
			'donacion' => 'ABH_SUPPORT_URL',
			'regalo'   => 'ABH_SUPPORT_GIFT_EMAIL',
		);
	}


	/**
	 * Engancha lo mínimo: recibir el formulario, y nada más.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'handle_post' ) );
	}


	/**
	 * Estado guardado, saneado.
	 *
	 * @return array
	 */
	public static function state() {
		if ( null !== self::$memo ) {
			return self::$memo;
		}
		$raw = get_option( self::OPTION, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		self::$memo = array(
			// 'ninguno' | 'apoyo' | 'nunca'. Nada de esto abre funciones.
			'estado'    => isset( $raw['estado'] ) && in_array( $raw['estado'], array( 'ninguno', 'apoyo', 'nunca' ), true )
				? $raw['estado']
				: 'ninguno',
			'desde'     => isset( $raw['desde'] ) ? (int) $raw['desde'] : 0,
			'pospuesto' => isset( $raw['pospuesto'] ) ? (int) $raw['pospuesto'] : 0,
		);
		return self::$memo;
	}


	/**
	 * Guarda el estado. Solo tres valores posibles y ninguno otorga nada.
	 *
	 * @param string $estado Nuevo estado.
	 * @return array Estado resultante.
	 */
	public static function set_state( $estado ) {
		$estado = (string) $estado;
		if ( ! in_array( $estado, array( 'ninguno', 'apoyo', 'nunca' ), true ) ) {
			return self::state();
		}
		$actual = self::state();
		$nuevo  = array(
			'estado'    => $estado,
			'desde'     => 'apoyo' === $estado ? time() : (int) $actual['desde'],
			'pospuesto' => (int) $actual['pospuesto'],
		);
		update_option( self::OPTION, $nuevo, false );
		self::$memo = null;
		return self::state();
	}


	/**
	 * Pospone la petición sin cerrarla para siempre.
	 *
	 * @return void
	 */
	public static function posponer() {
		$actual = self::state();
		update_option(
			self::OPTION,
			array(
				'estado'    => $actual['estado'],
				'desde'     => (int) $actual['desde'],
				'pospuesto' => time(),
			),
			false
		);
		self::$memo = null;
	}


	/**
	 * Un destino, ya resuelto y validado.
	 *
	 * Devuelve cadena vacía si no hay destino utilizable. Quien pinte la
	 * interfaz comprueba esto antes de dibujar nada: un botón que no lleva a
	 * ningún lado es peor que no tener botón.
	 *
	 * @param string $cual anual|donacion|regalo.
	 * @return string Validated URL or gift-recipient email, or ''.
	 */
	public static function destino( $cual ) {
		$defaults = self::defaults();
		$consts   = self::constantes();
		if ( ! isset( $defaults[ $cual ] ) ) {
			return '';
		}

		$valor = $defaults[ $cual ];
		if ( defined( $consts[ $cual ] ) ) {
			$valor = (string) constant( $consts[ $cual ] );
		}
		$valor = trim( $valor );
		if ( '' === $valor ) {
			return '';
		}

		if ( 'regalo' === $cual ) {
			if ( ! is_email( $valor ) ) {
				return '';
			}
			return sanitize_email( $valor );
		}

		$limpio = esc_url_raw( $valor, array( 'http', 'https' ) );
		if ( '' === $limpio || 0 !== strpos( $limpio, 'http' ) ) {
			return '';
		}
		return $limpio;
	}


	/**
	 * Address used only after a person explicitly chooses to prepare feedback.
	 *
	 * The plugin never sends the message. JavaScript opens the visitor's email
	 * application with a draft that they can review, edit, or discard.
	 *
	 * @return string Sanitized contact email.
	 */
	public static function feedback_email() {
		$email = defined( 'ABH_FEEDBACK_EMAIL' )
			? (string) constant( 'ABH_FEEDBACK_EMAIL' )
			: 'ostrovskyemmanuel@gmail.com';

		return is_email( $email ) ? sanitize_email( $email ) : '';
	}

	/**
	 * Los destinos que sí se pueden pintar.
	 *
	 * @return array Map of support type to validated destination.
	 */
	public static function destinos() {
		$out = array();
		foreach ( array_keys( self::defaults() ) as $cual ) {
			$url = self::destino( $cual );
			if ( '' !== $url ) {
				$out[ $cual ] = $url;
			}
		}
		return $out;
	}


	/**
	 * Lo que el plugin ya le ahorró a esta instalación.
	 *
	 * Sale del libro del medidor, no de una promesa de folleto: reparaciones
	 * que se resolvieron con motores deterministas, sin una sola llamada a
	 * ningún modelo, y los tokens que por eso no se pagaron.
	 *
	 * @return array
	 */
	public static function merito() {
		$vacio = array(
			'reparaciones' => 0,
			'tokens'       => 0,
			'costo'        => '',
			'incidencias'  => 0,
		);

		if ( ! class_exists( 'ABH_Meter' ) ) {
			return $vacio;
		}

		$t = ABH_Meter::totals();
		if ( ! is_array( $t ) ) {
			return $vacio;
		}

		return array(
			'reparaciones' => isset( $t['deterministic'] ) ? (int) $t['deterministic'] : 0,
			'tokens'       => isset( $t['avoided_total'] ) ? (int) $t['avoided_total'] : 0,
			'costo'        => isset( $t['cost_avoided'] ) ? (string) $t['cost_avoided'] : '',
			'incidencias'  => isset( $t['incidents'] ) ? (int) $t['incidents'] : 0,
		);
	}


	/**
	 * ¿Toca pedir apoyo?
	 *
	 * Solo si ya hizo algo por esta instalación, si no lo apagaron, si no
	 * apoyaron ya, si el descanso terminó y si de verdad hay a dónde mandar a
	 * la persona. Cinco condiciones para una sola pregunta.
	 *
	 * @return bool
	 */
	public static function should_ask() {
		$e = self::state();
		if ( 'ninguno' !== $e['estado'] ) {
			return false;
		}
		if ( $e['pospuesto'] > 0 && ( time() - $e['pospuesto'] ) < self::DESCANSO ) {
			return false;
		}
		if ( array() === self::destinos() ) {
			return false;
		}
		$m = self::merito();
		return $m['reparaciones'] >= self::UMBRAL_PARA_PEDIR;
	}


	/**
	 * Lo que el apoyo NO hace.
	 *
	 * Está en el código y no solo en la pantalla porque es la promesa central:
	 * ninguna capacidad del plugin depende de haber pagado. Cualquiera que
	 * intente atar una función a esto va a chocar contra esta función primero.
	 *
	 * @return bool Siempre false: el apoyo nunca concede permisos.
	 */
	public static function grants_anything() {
		return false;
	}


	/**
	 * Recibe el formulario de la pantalla de apoyo.
	 *
	 * @return void
	 */
	public static function handle_post() {
		if ( ! isset( $_POST['abh_support_action'] ) ) {
			return;
		}
		if ( ! ABH_Admin::can() ) {
			return;
		}
		if ( ! isset( $_POST['abh_support_nonce'] ) || ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['abh_support_nonce'] ) ), 'abh_support' ) ) {
			return;
		}

		$accion = sanitize_key( wp_unslash( $_POST['abh_support_action'] ) );

		if ( 'apoye' === $accion ) {
			self::set_state( 'apoyo' );
			add_settings_error( 'abh', 'abh_support', __( 'Thank you. No feature was turned on, because none was off: you already had them all.', 'ai-bug-hunter' ), 'success' );
			return;
		}

		if ( 'nunca' === $accion ) {
			self::set_state( 'nunca' );
			add_settings_error( 'abh', 'abh_support', __( 'Understood. It will not be mentioned again.', 'ai-bug-hunter' ), 'success' );
			return;
		}

		if ( 'despues' === $accion ) {
			self::posponer();
			add_settings_error( 'abh', 'abh_support', __( 'It is postponed.', 'ai-bug-hunter' ), 'info' );
		}
	}


	/**
	 * Limpia la memoria de proceso. Para pruebas.
	 *
	 * @return void
	 */
	public static function flush_cache() {
		self::$memo = null;
	}
}
