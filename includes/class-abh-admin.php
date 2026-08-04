<?php
/**
 * Interfaz de administración.
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ABH_Admin
 */
class ABH_Admin {

	const CAP = 'manage_options';

	/**
	 * Techo de incidencias que esta pantalla llega a procesar y pintar.
	 *
	 * Quien decide cuántas incidencias distintas hay NO es el operador: el
	 * registro lo escribe PHP, y basta un visitante sin autenticar provocando
	 * avisos para que crezca. ABH_Logs::scan() ya recorta la LECTURA a las
	 * últimas 3000 líneas, pero esas 3000 líneas pueden producir casi 3000
	 * incidencias distintas, y cada una cuesta varias consultas a disco al
	 * clasificarla —respaldo aplicado, mtime del fichero, estado de lint— más
	 * una tarjeta en el DOM al pintarla. Con eso, la pantalla que ofrece
	 * «Vaciar registro» y la limpieza selectiva se vuelve inusable justo cuando
	 * hace falta, y el operador se queda sin acceso al propio remedio.
	 *
	 * 200 es un orden de magnitud por encima de lo que acumula un sitio real
	 * con problemas de verdad, y ABH_Logs::parse() devuelve la lista ya
	 * ordenada por severidad y por frecuencia, así que el recorte se lleva
	 * siempre lo menos grave. Lo omitido se declara en pantalla: nunca se
	 * recorta en silencio.
	 */
	const MAX_INCIDENCIAS = 200;

	/**
	 * ¿Manda esta persona sobre TODO lo que este plugin puede escribir?
	 *
	 * ---------------------------------------------------------------------
	 * ESTE ES EL ÚNICO SITIO donde se decide quién es «el dueño». Capacidad y
	 * multisitio se responden juntos, aquí, y todo lo demás pregunta.
	 * ---------------------------------------------------------------------
	 *
	 * En una instalación normal 'manage_options' y «dueño del sitio» son la
	 * misma persona, así que la capacidad basta y la postura no cambia.
	 *
	 * En multisitio NO son la misma persona, y esa diferencia lo era todo:
	 * wp-content es COMPARTIDO por toda la red —los plugins y los temas de
	 * todos los sitios viven en la misma carpeta—, y un administrador de un
	 * solo sitio tiene 'manage_options' dentro del suyo. Sin esta comprobación,
	 * el administrador del blog más pequeño de la red podía escribir, revertir
	 * y borrar respaldos del código de TODOS los demás. Eso no es «administrar
	 * tu sitio»: es acceso de red, y de red sólo manda la superadministración.
	 *
	 * `is_super_admin()` se llama SÓLO en multisitio a propósito. En una
	 * instalación normal se apoya en 'delete_users', que los plugins de
	 * seguridad recortan, y dejaría al dueño fuera de su propia herramienta
	 * para protegerlo de una red que no existe.
	 *
	 * @return bool
	 */
	public static function can() {
		if ( ! current_user_can( self::CAP ) ) {
			return false;
		}
		if ( is_multisite() && ! is_super_admin() ) {
			return false;
		}
		return true;
	}

	/**
	 * Capacidad con la que se registran las pantallas del menú.
	 *
	 * add_menu_page() acepta una capacidad, no una llamada, así que no puede
	 * preguntar por can(). En multisitio se usa la única capacidad que tiene
	 * exactamente quien pasa can(): la de administrar la red. Registrar el menú
	 * con 'manage_options' y cerrar luego cada pantalla dejaría el menú entero a
	 * la vista de administradores de sitio que no pueden entrar en ninguna de
	 * sus páginas, que es prometer una herramienta y negarla en el clic.
	 *
	 * @return string
	 */
	public static function menu_cap() {
		return is_multisite() ? 'manage_network_options' : self::CAP;
	}

	/**
	 * Portero ÚNICO de las peticiones AJAX: capacidad y nonce.
	 *
	 * ---------------------------------------------------------------------
	 * ESTE ES EL ÚNICO SITIO donde se decide si una petición AJAX del plugin
	 * sigue adelante. Antes había varias copias del mismo control repartidas
	 * entre distintos endpoints. Centralizarlo evita reforzar una ruta y dejar
	 * otra con una política anterior.
	 *
	 * Si añades una comprobación de autorización, va AQUÍ. No dupliques.
	 * ---------------------------------------------------------------------
	 *
	 * Vive en ABH_Admin porque es quien declara quién puede mandar
	 * (self::can()) y no depende de ninguna de las tres clases que lo llaman:
	 * la flecha va siempre en un solo sentido. Ponerlo en ABH_Guard habría
	 * creado un ciclo, porque ABH_Admin ya usa ABH_Guard para revisar rutas
	 * y contenido.
	 *
	 * No devuelve: si algo falla corta la petición con 403.
	 *
	 * @param string $sin_permiso Mensaje cuando falta la capacidad. Vacío usa el general.
	 * @return void
	 */
	public static function guard_ajax_request( $sin_permiso = '' ) {
		if ( ! self::can() ) {
			if ( is_multisite() && current_user_can( self::CAP ) ) {
				// Tiene la capacidad y aun así no pasa. Decirle «no tienes
				// permisos» a alguien que sí administra su sitio es una pared sin
				// explicación: se dice el motivo real, que además es el único que
				// le sirve para saber a quién pedírselo. Este mensaje pisa el del
				// llamante a propósito, porque es más concreto que cualquiera.
				$sin_permiso = __( 'On a WordPress network this tool writes to wp-content, which belongs to ALL the sites on the network and not just yours. That is why it is handled by the network super admin, not by a single site\'s admin.', 'ai-bug-hunter' );
			} elseif ( '' === $sin_permiso ) {
				$sin_permiso = __( 'You do not have permission to do this.', 'ai-bug-hunter' );
			}
			wp_send_json_error( array( 'message' => $sin_permiso ), 403 );
		}
		$nonce = isset( $_POST['nonce'] ) ? sanitize_key( wp_unslash( $_POST['nonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'abh_nonce' ) ) {
			wp_send_json_error( array( 'message' => __( 'The session expired. Reload the page.', 'ai-bug-hunter' ) ), 403 );
		}
	}

	/**
	 * Engancha los hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_init', array( __CLASS__, 'save_settings' ) );
		add_action( 'admin_footer', array( __CLASS__, 'render_repair_console' ) );
		// Una credencial guardada en un campo público es una fuga activa: se
		// avisa en TODA la administración, no solo dentro del plugin.
		add_action( 'admin_notices', array( __CLASS__, 'notice_public_field_secret' ) );
		// Los avisos de otros plugins ya NO se desenganchan. Desregistrar el
		// callback de un tercero es invasivo —le quita su aviso aunque lo
		// necesite— y la directriz 11 de WordPress.org lo rechaza de plano. En
		// este árbol no queda ni un solo remove_action sobre 'admin_notices'.
		//
		// Lo que se hace en su lugar, para que conste exacto y nadie lo lea de
		// más: (a) admin.css colapsa a la vista los avisos de TGMPA dentro de
		// nuestras pantallas —display:none, el nodo se queda donde estaba y
		// quien lo pintó puede seguir leyéndolo—; y (b) dashboard.js MUEVE los
		// avisos ajenos a una bandeja propia con appendTo(), donde siguen
		// visibles, contados y accesibles. Es decir: se reubica el nodo ajeno,
		// pero no se borra ninguno ni se toca el hook de nadie. La rutina que
		// BORRABA los avisos de TGMPA se retiró y no debe volver.
	}

	/**
	 * Avisa cuando el modelo o la URL base contienen algo con forma de clave.
	 *
	 * @return void
	 */
	public static function notice_public_field_secret() {
		if ( ! self::can() ) {
			return;
		}
		if ( ! class_exists( 'ABH_Router' ) || ! class_exists( 'ABH_Privacy' ) ) {
			return;
		}
		// Se lee la opción cruda a propósito. ABH_Router::settings() descifra la
		// clave y puede escribir una migración: eso no puede ocurrir en cada
		// pantalla de la administración solo para pintar un aviso.
		$raw   = get_option( 'abh_settings', array() );
		$raw   = is_array( $raw ) ? $raw : array();
		$field = ABH_Router::public_field_secret(
			array(
				'model'    => isset( $raw['model'] ) ? (string) $raw['model'] : '',
				'base_url' => isset( $raw['base_url'] ) ? (string) $raw['base_url'] : '',
			)
		);
		if ( '' === $field ) {
			return;
		}
		$url = admin_url( 'admin.php?page=' . ABH_SLUG . '-settings' );
		echo '<div class="notice notice-error"><p><strong>'
			. esc_html( ABH_PRODUCT_NAME )
			. ': '
			. esc_html__( 'there is a credential stored in a public field.', 'ai-bug-hunter' )
			. '</strong></p><p>'
			. esc_html( ABH_Router::public_field_secret_message( $field ) )
			. '</p><p>'
			. esc_html__( 'That value has been shown on screen, is stored unencrypted in the database and ends up inside every backup. Revoke the credential in your provider\'s dashboard before fixing the field.', 'ai-bug-hunter' )
			. '</p><p><a class="button button-primary" href="' . esc_url( $url ) . '">'
			. esc_html__( 'Fix in Settings', 'ai-bug-hunter' )
			. '</a></p></div>';
	}

	/**
	 * Menú del panel.
	 *
	 * @return void
	 */
	public static function menu() {
		$cap = self::menu_cap();
		add_menu_page(
			ABH_PRODUCT_NAME,
			ABH_PRODUCT_NAME,
			$cap,
			ABH_SLUG,
			array( __CLASS__, 'page_diagnostico' ),
			'dashicons-search',
			76
		);
		add_submenu_page( ABH_SLUG, __( 'Summary', 'ai-bug-hunter' ), __( 'Summary', 'ai-bug-hunter' ), $cap, ABH_SLUG, array( __CLASS__, 'page_diagnostico' ) );
		add_submenu_page( ABH_SLUG, __( 'History', 'ai-bug-hunter' ), __( 'History', 'ai-bug-hunter' ), $cap, ABH_SLUG . '-historial', array( __CLASS__, 'page_historial' ) );
		add_submenu_page( ABH_SLUG, __( 'Security', 'ai-bug-hunter' ), __( 'Security', 'ai-bug-hunter' ), $cap, ABH_SLUG . '-seguridad', array( __CLASS__, 'page_seguridad' ) );
		add_submenu_page( ABH_SLUG, __( 'Settings', 'ai-bug-hunter' ), __( 'Settings', 'ai-bug-hunter' ), $cap, ABH_SLUG . '-settings', array( __CLASS__, 'page_ajustes' ) );
		add_submenu_page( ABH_SLUG, __( 'Support', 'ai-bug-hunter' ), __( 'Support', 'ai-bug-hunter' ), $cap, ABH_SLUG . '-apoyo', array( __CLASS__, 'page_apoyo' ) );
	}

	/**
	 * Carga estilos y scripts solo en nuestras pantallas.
	 *
	 * @param string $hook Pantalla actual.
	 * @return void
	 */
	public static function assets( $hook ) {
		if ( false === strpos( $hook, ABH_SLUG ) ) {
			return;
		}
		wp_enqueue_style( 'abh-admin', ABH_URL . 'assets/admin.css', array(), ABH_ASSET_VERSION );
		wp_enqueue_script( 'abh-admin', ABH_URL . 'assets/admin.js', array( 'jquery' ), ABH_ASSET_VERSION, true );
		// Efectos de la consola. Va en TODAS las pantallas del plugin porque la
		// consola también se pinta en todas (ver render_repair_console): dejarlo
		// solo en el diagnóstico daría una consola viva en una pantalla y muerta
		// en la siguiente, que es exactamente el fallo que tenía el modal de
		// firma root. No depende de jQuery: solo observa el DOM ya pintado.
		wp_enqueue_script( 'abh-console-fx', ABH_URL . 'assets/console-fx.js', array( 'abh-admin' ), ABH_ASSET_VERSION, true );
		$is_diagnostic = isset( $_GET['page'] ) && ABH_SLUG === sanitize_key( wp_unslash( $_GET['page'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $is_diagnostic ) {
			wp_enqueue_style( 'abh-dashboard', ABH_URL . 'assets/dashboard.css', array( 'abh-admin' ), ABH_ASSET_VERSION );
			wp_enqueue_script( 'abh-dashboard', ABH_URL . 'assets/dashboard.js', array( 'abh-admin' ), ABH_ASSET_VERSION, true );
		}
		wp_localize_script(
			'abh-admin',
			'ABH',
			array(
				'ajax'    => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'abh_nonce' ),
				'version' => ABH_VERSION,
				'edition' => ABH_Edition::ID,
				'can_apply_external_repairs' => ABH_Edition::can_apply_external_repairs(),
				// Reparación a medias del usuario: sobrevive a la recarga para no
				// tirar a la basura lo que ya se le pagó al modelo.
				'active'  => ABH_Thoth_AI::active_job(),
				'urls'  => array(
					'diagnostic' => admin_url( 'admin.php?page=' . ABH_SLUG ),
					'history'    => admin_url( 'admin.php?page=' . ABH_SLUG . '-historial' ),
					'site'       => home_url( '/' ),
				),
				'i18n'  => array(
					'analizando'  => __( 'Analyzing…', 'ai-bug-hunter' ),
					'aplicando'   => __( 'Applying…', 'ai-bug-hunter' ),
					'confirmar'   => __( 'Apply this change to your site?', 'ai-bug-hunter' ),
					'revertir'    => __( 'Revert this change?', 'ai-bug-hunter' ),
					'error'       => __( 'An unexpected error occurred.', 'ai-bug-hunter' ),
					'sin_cambios' => __( 'No changes', 'ai-bug-hunter' ),
				),
			)
		);
	}


	/**
	 * Renderiza la consola una sola vez en las pantallas del plugin.
	 *
	 * No es una shell: solo muestra eventos verificados y acciones permitidas.
	 *
	 * @return void
	 */
	public static function render_repair_console() {
		if ( ! self::can() ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || false === strpos( (string) $screen->id, ABH_SLUG ) ) {
			return;
		}
		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		?>
		<div id="abh-console" class="abh-console" aria-hidden="true">
			<div class="abh-console-backdrop" data-console-close></div>
			<section class="abh-console-window" role="dialog" aria-modal="true" aria-labelledby="abh-console-title">
				<header class="abh-console-topbar">
					<div class="abh-console-product">
						<img src="<?php echo esc_url( ABH_URL . 'assets/brand/hunter-avatar.png' ); ?>" alt="">
						<div>
							<div class="abh-console-product-name"><strong id="abh-console-title"><?php echo esc_html( ABH_PRODUCT_NAME ); ?></strong><span>v<?php echo esc_html( ABH_VERSION ); ?></span></div>
							<p><?php esc_html_e( 'Analysis console and clear repair help', 'ai-bug-hunter' ); ?></p>
						</div>
					</div>

					<div class="abh-console-context" aria-label="<?php esc_attr_e( 'Session context', 'ai-bug-hunter' ); ?>">
						<div><small><?php esc_html_e( 'SESSION', 'ai-bug-hunter' ); ?></small><strong id="abh-console-job"><?php esc_html_e( 'Session not started yet', 'ai-bug-hunter' ); ?></strong></div>
						<div><small><?php esc_html_e( 'TARGET', 'ai-bug-hunter' ); ?></small><strong id="abh-console-target"><?php echo esc_html( $host ? $host : __( 'Current site', 'ai-bug-hunter' ) ); ?></strong></div>
						<div class="is-route"><small><?php esc_html_e( 'CURRENT PATH', 'ai-bug-hunter' ); ?></small><strong id="abh-console-route"><?php esc_html_e( 'Pending identification', 'ai-bug-hunter' ); ?></strong></div>
						<div><small><?php esc_html_e( 'MODE', 'ai-bug-hunter' ); ?></small><strong id="abh-console-mode"><?php esc_html_e( 'Analysis · Safe plan', 'ai-bug-hunter' ); ?></strong></div>
						<div><small><?php esc_html_e( 'SCAN STATUS', 'ai-bug-hunter' ); ?></small><strong id="abh-console-scan-state" class="is-working"><span aria-hidden="true"></span><?php esc_html_e( 'Preparing…', 'ai-bug-hunter' ); ?></strong></div>
					</div>

					<div class="abh-console-global-actions">
						<button type="button" class="button" id="abh-console-pause" aria-pressed="false" title="<?php esc_attr_e( 'This only pauses the visual playback; the analysis on the server continues.', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-controls-pause" aria-hidden="true"></span><span><?php esc_html_e( 'Pause', 'ai-bug-hunter' ); ?></span></button>
						<button type="button" class="button abh-console-menu" aria-label="<?php esc_attr_e( 'More options', 'ai-bug-hunter' ); ?>" disabled><span class="dashicons dashicons-ellipsis" aria-hidden="true"></span></button>
						<button type="button" class="abh-console-close" data-console-close aria-label="<?php esc_attr_e( 'Close console', 'ai-bug-hunter' ); ?>">×</button>
					</div>
				</header>

				<div class="abh-console-progress" aria-label="<?php esc_attr_e( 'Repair progress', 'ai-bug-hunter' ); ?>">
					<span id="abh-console-progress-bar"></span>
				</div>

				<nav class="abh-console-tabs" aria-label="<?php esc_attr_e( 'Console views', 'ai-bug-hunter' ); ?>">
					<div class="abh-console-tab-list" role="tablist">
						<button type="button" class="abh-console-tab is-active" id="abh-console-tab-analysis" role="tab" aria-selected="true" aria-controls="abh-console-view-analysis" data-console-tab="analysis"><?php esc_html_e( 'Analysis console', 'ai-bug-hunter' ); ?></button>
						<button type="button" class="abh-console-tab" id="abh-console-tab-events" role="tab" aria-selected="false" aria-controls="abh-console-view-events" data-console-tab="events"><?php esc_html_e( 'Event view', 'ai-bug-hunter' ); ?></button>
					</div>
					<div class="abh-console-tab-tools">
						<label><span><?php esc_html_e( 'Auto-scroll', 'ai-bug-hunter' ); ?></span><input type="checkbox" id="abh-console-autoscroll" checked><i aria-hidden="true"></i></label>
						<button type="button" class="button-link" id="abh-console-filter" disabled><span class="dashicons dashicons-filter" aria-hidden="true"></span><?php esc_html_e( 'Filters', 'ai-bug-hunter' ); ?></button>
					</div>
				</nav>

				<div class="abh-console-views">
					<section class="abh-console-view is-active" id="abh-console-view-analysis" role="tabpanel" aria-labelledby="abh-console-tab-analysis" data-console-view="analysis">
						<div class="abh-console-layout">
							<div class="abh-console-terminal-wrap">
								<div class="abh-console-terminal" id="abh-console-terminal" role="log" aria-live="polite" aria-relevant="additions"></div>

								<?php if ( ABH_Chat::allowed() ) : ?>
								<?php $abh_libre = ABH_Chat::superadmin(); ?>
								<form class="abh-console-prompt<?php echo $abh_libre ? '' : ' is-gated'; ?>" id="abh-console-prompt" data-gated="<?php echo $abh_libre ? 'siempre' : '1'; ?>">
									<label class="screen-reader-text" for="abh-console-input"><?php esc_html_e( 'Type your question in the terminal', 'ai-bug-hunter' ); ?></label>
									<span class="abh-console-prompt-sign" aria-hidden="true">ai-bug-hunter:~$</span>
									<input type="text" id="abh-console-input" autocomplete="off" spellcheck="false" maxlength="4000" <?php echo $abh_libre ? '' : 'disabled'; ?> placeholder="<?php echo esc_attr( $abh_libre ? __( 'Ask about the analysis — Enter to send', 'ai-bug-hunter' ) : __( 'Enabled once there is a specific diagnosis', 'ai-bug-hunter' ) ); ?>">
									<button type="submit" class="button" id="abh-console-send" <?php echo $abh_libre ? '' : 'disabled'; ?>><?php esc_html_e( 'Send', 'ai-bug-hunter' ); ?></button>
									<button type="button" class="button abh-btn-verde" id="abh-console-manual-guide-inline" hidden><?php esc_html_e( 'What should I do?', 'ai-bug-hunter' ); ?></button>
									<?php
									// La acción azul de aprobación se refleja aquí y la original
									// del pie queda oculta. Es un solo manejador y una sola puerta:
									// no hay un botón verde alternativo que pueda saltarse pasos.
									?>
									<button type="button" class="button button-primary" id="abh-console-aplicar" hidden><?php esc_html_e( 'Repair installation', 'ai-bug-hunter' ); ?></button>
								</form>
								<?php endif; ?>

								<div class="abh-console-help">
									<span><?php esc_html_e( 'This console explains verified events and accepts questions only.', 'ai-bug-hunter' ); ?></span>
									<div class="abh-console-playback" aria-label="<?php esc_attr_e( 'Console reading controls', 'ai-bug-hunter' ); ?>">
										<span id="abh-console-pace-status"><?php esc_html_e( 'Automatic pace', 'ai-bug-hunter' ); ?></span>
										<button type="button" class="button-link" id="abh-console-toggle-pace"><?php esc_html_e( 'Change pace', 'ai-bug-hunter' ); ?></button>
										<button type="button" class="button-link" id="abh-console-show-all"><?php esc_html_e( 'Show all', 'ai-bug-hunter' ); ?></button>
										<button type="button" class="button-link" id="abh-console-explain-hash"><?php esc_html_e( 'What is SHA-256?', 'ai-bug-hunter' ); ?></button>
									</div>
								</div>
							</div>

							<aside class="abh-console-panel" id="abh-console-panel" aria-label="<?php esc_attr_e( 'Contextual summary of the analysis', 'ai-bug-hunter' ); ?>">
								<section class="abh-console-summary-card is-hypothesis" data-console-summary="hypothesis">
									<header><span class="dashicons dashicons-lightbulb" aria-hidden="true"></span><strong><?php esc_html_e( 'HYPOTHESIS', 'ai-bug-hunter' ); ?></strong><small id="abh-console-confidence"><?php esc_html_e( 'Confidence: pending', 'ai-bug-hunter' ); ?></small></header>
									<div class="abh-console-summary-body" id="abh-console-summary-hypothesis"><p><?php esc_html_e( 'HUNTER AI will show here what it believes is happening and which questions remain open.', 'ai-bug-hunter' ); ?></p></div>
								</section>
								<section class="abh-console-summary-card is-cause" data-console-summary="cause">
									<header><span class="dashicons dashicons-admin-generic" aria-hidden="true"></span><strong><?php esc_html_e( 'ROOT CAUSE', 'ai-bug-hunter' ); ?></strong></header>
									<div class="abh-console-summary-body" id="abh-console-summary-cause"><p><?php esc_html_e( 'Pending confirmation with evidence from the code and the environment.', 'ai-bug-hunter' ); ?></p></div>
								</section>
								<section class="abh-console-summary-card is-evidence" data-console-summary="evidence">
									<header><span class="dashicons dashicons-media-document" aria-hidden="true"></span><strong><?php esc_html_e( 'KEY EVIDENCE', 'ai-bug-hunter' ); ?></strong><button type="button" class="button-link" data-console-tab-jump="events"><?php esc_html_e( 'View all', 'ai-bug-hunter' ); ?></button></header>
									<div class="abh-console-summary-body" id="abh-console-summary-evidence"><p><?php esc_html_e( 'Verified evidence will appear as the review progresses.', 'ai-bug-hunter' ); ?></p></div>
								</section>
								<section class="abh-console-summary-card is-plan" data-console-summary="plan">
									<header><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span><strong><?php esc_html_e( 'SAFE PLAN (DRY-RUN)', 'ai-bug-hunter' ); ?></strong><small id="abh-console-plan-state"><?php esc_html_e( 'No changes applied', 'ai-bug-hunter' ); ?></small></header>
									<div class="abh-console-summary-body" id="abh-console-summary-plan"><p><?php esc_html_e( 'The plan will appear after Analyst, Skeptic and Referee finish their review.', 'ai-bug-hunter' ); ?></p></div>
								</section>
								<section class="abh-console-summary-card is-risk" data-console-summary="risk">
									<header><span class="dashicons dashicons-shield" aria-hidden="true"></span><strong><?php esc_html_e( 'RISK', 'ai-bug-hunter' ); ?></strong><small id="abh-console-risk-state"><?php esc_html_e( 'Pending evaluation', 'ai-bug-hunter' ); ?></small></header>
									<div class="abh-console-summary-body" id="abh-console-summary-risk"><p><?php esc_html_e( 'No severity will be assigned until there is enough evidence.', 'ai-bug-hunter' ); ?></p></div>
								</section>
							</aside>
						</div>
					</section>

					<section class="abh-console-view" id="abh-console-view-events" role="tabpanel" aria-labelledby="abh-console-tab-events" data-console-view="events" hidden>
						<div class="abh-console-events-head"><div><strong><?php esc_html_e( 'Phase history', 'ai-bug-hunter' ); ?></strong><p><?php esc_html_e( 'Every phase is kept so that a new conclusion does not replace the earlier evidence.', 'ai-bug-hunter' ); ?></p></div><nav class="abh-console-phase-nav" id="abh-console-phase-nav" aria-label="<?php esc_attr_e( 'Review phases', 'ai-bug-hunter' ); ?>"></nav></div>
						<div class="abh-console-phase-history" id="abh-console-phase-history"><div class="abh-console-empty"><strong><?php esc_html_e( 'Preparing the history', 'ai-bug-hunter' ); ?></strong><p><?php esc_html_e( 'Analyst, Skeptic, Evidence Collector and Referee will appear here as they finish.', 'ai-bug-hunter' ); ?></p></div></div>
					</section>
				</div>

				<footer class="abh-console-footer">
					<div class="abh-console-status-grid">
						<div class="abh-console-status-module is-integrity"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span><div><small><?php esc_html_e( 'SYSTEM INTEGRITY', 'ai-bug-hunter' ); ?></small><strong id="abh-console-integrity">OK</strong><p><?php esc_html_e( 'All modules operational', 'ai-bug-hunter' ); ?></p></div></div>
						<div class="abh-console-status-module"><span class="dashicons dashicons-privacy" aria-hidden="true"></span><div><small><?php esc_html_e( 'FILE FINGERPRINT', 'ai-bug-hunter' ); ?></small><strong id="abh-console-fingerprint"><?php esc_html_e( 'Pending', 'ai-bug-hunter' ); ?></strong><p><?php esc_html_e( 'Identity before the change', 'ai-bug-hunter' ); ?></p></div></div>
						<div class="abh-console-status-module"><span class="dashicons dashicons-editor-code" aria-hidden="true"></span><div><small><?php esc_html_e( 'CURRENT MODE', 'ai-bug-hunter' ); ?></small><strong class="is-dry-run">DRY-RUN</strong><p><?php esc_html_e( 'Analysis only, no modifications', 'ai-bug-hunter' ); ?></p></div></div>
						<div class="abh-console-status-module"><span class="dashicons dashicons-randomize" aria-hidden="true"></span><div><small><?php esc_html_e( 'CHANGES', 'ai-bug-hunter' ); ?></small><strong class="abh-console-state is-safe" id="abh-console-state"><?php esc_html_e( 'No changes applied', 'ai-bug-hunter' ); ?></strong><p><?php esc_html_e( 'The system remains intact', 'ai-bug-hunter' ); ?></p></div></div>
						<div class="abh-console-status-module is-hunter"><img src="<?php echo esc_url( ABH_URL . 'assets/brand/hunter-avatar.png' ); ?>" alt=""><div><strong><?php esc_html_e( 'Hunter is learning.', 'ai-bug-hunter' ); ?></strong><p><?php esc_html_e( 'Improving its red team thinking.', 'ai-bug-hunter' ); ?></p></div></div>
					</div>
					<div class="abh-console-actions" id="abh-console-actions">
						<button type="button" class="button" id="abh-console-download-log" disabled><?php esc_html_e( 'Download log', 'ai-bug-hunter' ); ?></button>
						<button type="button" class="button" data-console-close><?php esc_html_e( 'Close', 'ai-bug-hunter' ); ?></button>
					</div>
				</footer>
			</section>
			<section class="abh-manual-guide-modal" id="abh-manual-guide-modal" role="dialog" aria-modal="true" aria-labelledby="abh-manual-guide-title" hidden>
				<div class="abh-manual-guide-backdrop" data-manual-guide-close></div>
				<div class="abh-manual-guide-window">
					<header>
						<div>
							<span class="abh-manual-guide-eyebrow"><?php esc_html_e( 'WORDPRESS.ORG EDITION · READ ONLY', 'ai-bug-hunter' ); ?></span>
							<h2 id="abh-manual-guide-title"><?php esc_html_e( 'Repair help', 'ai-bug-hunter' ); ?></h2>
							<p><?php esc_html_e( 'Clear next steps first, with optional technical details below. The plugin will not apply changes.', 'ai-bug-hunter' ); ?></p>
						</div>
						<button type="button" class="abh-manual-guide-close" data-manual-guide-close aria-label="<?php esc_attr_e( 'Close guide', 'ai-bug-hunter' ); ?>">&times;</button>
					</header>
					<div class="abh-manual-guide-body" id="abh-manual-guide-body" aria-live="polite"></div>
					<footer>
						<button type="button" class="button" id="abh-manual-guide-download"><?php esc_html_e( 'Download guide', 'ai-bug-hunter' ); ?></button>
						<button type="button" class="button" id="abh-manual-guide-download-diff" hidden><?php esc_html_e( 'Download diff', 'ai-bug-hunter' ); ?></button>
						<button type="button" class="button button-primary" data-manual-guide-close><?php esc_html_e( 'Got it', 'ai-bug-hunter' ); ?></button>
					</footer>
				</div>
			</section>
		</div>
		<?php
	}

	/**
	 * Guarda los ajustes.
	 *
	 * @return void
	 */
	public static function save_settings() {
		if ( ! isset( $_POST['abh_settings_nonce'] ) ) {
			return;
		}
		if ( ! self::can() ) {
			add_settings_error( 'abh', 'cap', __( 'Not saved: your user does not have administrator permissions.', 'ai-bug-hunter' ) );
			return;
		}
		if ( ! wp_verify_nonce( sanitize_key( wp_unslash( $_POST['abh_settings_nonce'] ) ), 'abh_save_settings' ) ) {
			add_settings_error( 'abh', 'nonce', __( 'Not saved: the page had been open too long (or a cache interfered). Enter the data again and save once more.', 'ai-bug-hunter' ) );
			return;
		}

		$key       = isset( $_POST['abh_api_key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['abh_api_key'] ) ) ) : '';
		$clear_key = isset( $_POST['abh_clear_api_key'] );

		$new = array(
			'provider'                  => isset( $_POST['abh_provider'] ) ? sanitize_key( wp_unslash( $_POST['abh_provider'] ) ) : '',
			'model'                     => isset( $_POST['abh_model'] ) ? sanitize_text_field( wp_unslash( $_POST['abh_model'] ) ) : '',
			'base_url'                  => isset( $_POST['abh_base_url'] ) ? esc_url_raw( wp_unslash( $_POST['abh_base_url'] ) ) : '',
			'custom_endpoint_confirmed' => isset( $_POST['abh_endpoint_confirmed'] ) ? 1 : 0,
			'allow_private_endpoint'     => isset( $_POST['abh_allow_private'] ) ? 1 : 0,
			'external_service_consent'  => isset( $_POST['abh_external_service_consent'] ) ? 1 : 0,
			'accepted'                  => isset( $_POST['abh_accepted'] ) ? 1 : 0,
			'wipe_on_uninstall'          => isset( $_POST['abh_wipe'] ) ? 1 : 0,
			'price_in'                  => isset( $_POST['abh_price_in'] ) ? (float) str_replace( ',', '.', sanitize_text_field( wp_unslash( $_POST['abh_price_in'] ) ) ) : 0,
			'price_out'                 => isset( $_POST['abh_price_out'] ) ? (float) str_replace( ',', '.', sanitize_text_field( wp_unslash( $_POST['abh_price_out'] ) ) ) : 0,
		);

		$saved = ABH_Router::save_settings( $new, $key, $clear_key );
		if ( empty( $saved['ok'] ) ) {
			add_settings_error( 'abh', 'save_failed', $saved['error'] );
			return;
		}
		$new = $saved['settings'];

		// Confirmación honesta: guardado ≠ configurado.
		if ( ABH_Router::is_configured( $new ) ) {
			add_settings_error( 'abh', 'saved', __( 'Settings saved securely. Use “Test connection” to verify the provider.', 'ai-bug-hunter' ), 'updated' );
		} else {
			$falta = array();
			if ( empty( $new['provider'] ) ) {
				$falta[] = __( 'the provider', 'ai-bug-hunter' );
			}
			if ( empty( $new['external_service_consent'] ) ) {
				$falta[] = __( 'consent for external communication', 'ai-bug-hunter' );
			}
			if ( empty( $new['model'] ) ) {
				$falta[] = __( 'the model', 'ai-bug-hunter' );
			}
			if ( 'compatible' === $new['provider'] ) {
				if ( empty( $new['base_url'] ) ) {
					$falta[] = __( 'the base URL', 'ai-bug-hunter' );
				}
				if ( empty( $new['custom_endpoint_confirmed'] ) ) {
					$falta[] = __( 'the confirmation of the custom endpoint', 'ai-bug-hunter' );
				}
			} elseif ( ! empty( $new['provider'] ) && empty( $new['api_key'] ) ) {
				$falta[] = __( 'the API key', 'ai-bug-hunter' );
			}
			/* translators: %s: lista de campos que faltan. */
			add_settings_error( 'abh', 'saved_incomplete', sprintf( __( 'Settings saved, but still missing: %s.', 'ai-bug-hunter' ), implode( ', ', $falta ) ) );
		}
	}

	/**
	 * Cabecera común.
	 *
	 * @param string $titulo    Título.
	 * @param array  $dashboard Datos opcionales del dashboard.
	 * @return void
	 */
	private static function header( $titulo, $dashboard = array() ) {
		if ( ! empty( $dashboard ) ) {
			ABH_Dashboard::render_header( $titulo, $dashboard );
		} else {
			?>
			<div class="abh-head">
				<div class="abh-brand">
					<div class="abh-brand-avatar" aria-hidden="true">
						<img src="<?php echo esc_url( ABH_URL . 'assets/brand/hunter-avatar.png' ); ?>" alt="">
					</div>
					<div class="abh-brand-copy">
						<div class="abh-brand-eyebrow">
							<span><?php echo esc_html( ABH_PRODUCT_NAME ); ?></span>
							<span aria-hidden="true">·</span>
							<span><?php echo esc_html( sprintf( /* translators: %s: product engine name. */ __( '%s is the analysis engine', 'ai-bug-hunter' ), ABH_ENGINE_NAME ) ); ?></span>
						</div>
						<h1>
							<span><?php echo esc_html( $titulo ); ?></span>
							<span class="abh-version">v<?php echo esc_html( ABH_VERSION ); ?></span>
						</h1>
						<p class="abh-sub"><?php esc_html_e( 'It observes, explains and prepares reversible changes. It never modifies wp-config.php and never applies a repair without showing it to you first.', 'ai-bug-hunter' ); ?></p>
					</div>
				</div>
			</div>
			<?php
		}
		settings_errors( 'abh' );

		// Aquí se pintaba la tira de saldo de ABH_Status_UI. Esa clase no forma
		// parte de esta edición —scripts/build-releases.ps1 la excluye del
		// paquete público—, así que la rama nunca se cumplía: se retira entera.
		//
		// Lo que sí sigue valiendo para cualquier cosa que se añada aquí: no la
		// sirvas como `.notice`. dashboard.js recoge todo `.notice` bajo
		// #wpbody-content y lo pliega en una bandeja, así que un contador
		// servido como aviso se plegaría justo en la pantalla más visitada.
		if ( ! ABH_Router::is_configured() ) {
			?>
			<div class="notice notice-warning abh-notice">
				<p>
					<strong><?php esc_html_e( 'An AI model still needs to be connected.', 'ai-bug-hunter' ); ?></strong>
					<?php esc_html_e( 'Log diagnosis works without AI, but to propose fixes you need to connect your provider.', 'ai-bug-hunter' ); ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . ABH_SLUG . '-settings' ) ); ?>"><?php esc_html_e( 'Go to Settings', 'ai-bug-hunter' ); ?></a>
				</p>
			</div>
			<?php
		}

		// Se pide apoyo solo después de haber arreglado algo sin cobrar tokens,
		// y una sola vez: la propia pantalla trae el botón para callarlo.
		if ( class_exists( 'ABH_Support' ) && ABH_Support::should_ask() ) {
			$abh_merito = ABH_Support::merito();
			?>
			<div class="notice notice-info abh-notice">
				<p>
					<strong>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: número de reparaciones. */
								_n(
									'This plugin has already resolved %s error without spending a single token.',
									'This plugin has already resolved %s errors without spending a single token.',
									$abh_merito['reparaciones'],
									'ai-bug-hunter'
								),
								number_format_i18n( $abh_merito['reparaciones'] )
							)
						);
						?>
					</strong>
					<?php esc_html_e( 'It is free and it will stay that way. If you want to support it, there is a page for that.', 'ai-bug-hunter' ); ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . ABH_SLUG . '-apoyo' ) ); ?>"><?php esc_html_e( 'See how to support', 'ai-bug-hunter' ); ?></a>
				</p>
			</div>
			<?php
		}
	}


	/**
	 * Duración legible del escaneo.
	 *
	 * @param int $seconds Segundos.
	 * @return string
	 */
	private static function format_duration( $seconds ) {
		$seconds = max( 0, (int) $seconds );
		if ( $seconds < 60 ) {
			return sprintf( /* translators: %d: duration in seconds. */ __( '%d s', 'ai-bug-hunter' ), $seconds );
		}
		return sprintf( /* translators: 1: whole minutes, 2: remaining seconds. */ __( '%1$d min %2$d s', 'ai-bug-hunter' ), floor( $seconds / 60 ), $seconds % 60 );
	}

	/**
	 * Sección de escaneo sintáctico independiente del debug.log.
	 *
	 * @return void
	 */
	private static function render_syntax_scan() {
		$report   = ABH_Scanner::last_report();
		$findings = ABH_Scanner::fresh_findings( $report );
		$scanned  = isset( $report['scanned'] ) ? (int) $report['scanned'] : 0;
		$duration = isset( $report['duration'] ) ? (int) $report['duration'] : 0;
		$at       = isset( $report['completed_at'] ) ? (int) $report['completed_at'] : 0;
		?>
		<section class="abh-scan-card">
			<div class="abh-scan-head">
				<div class="abh-scan-title">
							<div><h2><?php esc_html_e( 'PHP file scan', 'ai-bug-hunter' ); ?></h2><span class="abh-chip-thoth is-local"><?php esc_html_e( 'HUNTER AI · local scanner available', 'ai-bug-hunter' ); ?></span></div>
					<p><?php esc_html_e( 'We analyze every PHP file in your WordPress installation looking for syntax errors and damaged files. All the analysis happens on your own server.', 'ai-bug-hunter' ); ?></p>
				</div>
				<div class="abh-scan-actions">
					<button type="button" class="button button-primary abh-syntax-scan" data-scope="quick"><span class="dashicons dashicons-controls-play"></span><?php esc_html_e( 'Scan now', 'ai-bug-hunter' ); ?></button>
					<?php // «Vaciar registro» no es una acción de escaneo y vivía aquí por costumbre: ahora está en render_log_controls(), que se pinta antes que nada y no depende de ninguna lista. ?>
					<button type="button" class="button abh-syntax-scan" data-scope="full"><span class="dashicons dashicons-marker"></span><?php esc_html_e( 'Full scan', 'ai-bug-hunter' ); ?></button>
				</div>
			</div>

			<?php if ( ! empty( $report ) ) : ?>
				<div class="abh-scan-result <?php echo empty( $findings ) ? 'is-clean' : 'has-findings'; ?>">
					<div class="abh-scan-result-main"><span class="dashicons <?php echo empty( $findings ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span><div><strong><?php echo esc_html( empty( $findings ) ? __( 'Scan completed successfully', 'ai-bug-hunter' ) : sprintf( /* translators: %d: active finding count. */ _n( '%d active finding', '%d active findings', count( $findings ), 'ai-bug-hunter' ), count( $findings ) ) ); ?></strong><span><?php echo esc_html( sprintf( /* translators: 1: scanned file count, 2: scan duration. */ __( '%1$s files analyzed in %2$s', 'ai-bug-hunter' ), number_format_i18n( $scanned ), self::format_duration( $duration ) ) ); ?></span></div></div>
					<div class="abh-scan-result-time"><span class="dashicons dashicons-clock"></span><div><small><?php esc_html_e( 'Last scan', 'ai-bug-hunter' ); ?></small><strong><?php echo esc_html( $at ? wp_date( 'j M Y, H:i:s', $at ) : __( 'No date', 'ai-bug-hunter' ) ); ?></strong></div></div>
					<button type="button" class="button abh-open-scan-summary" aria-haspopup="dialog" aria-controls="abh-scan-summary-modal" aria-expanded="false"><?php esc_html_e( 'View scan details', 'ai-bug-hunter' ); ?><span class="dashicons dashicons-arrow-right-alt2" aria-hidden="true"></span></button>
				</div>
				<div class="abh-scan-summary-modal" id="abh-scan-summary-modal" role="dialog" aria-modal="true" aria-labelledby="abh-scan-summary-title" hidden>
					<div class="abh-scan-summary-backdrop" data-abh-close-scan-summary></div>
					<div class="abh-scan-summary-dialog" role="document">
						<header>
							<div>
								<span class="abh-scan-summary-kicker"><?php esc_html_e( 'LAST SCAN', 'ai-bug-hunter' ); ?></span>
								<h2 id="abh-scan-summary-title"><?php esc_html_e( 'Scan summary', 'ai-bug-hunter' ); ?></h2>
							</div>
							<button type="button" class="abh-scan-summary-close" data-abh-close-scan-summary aria-label="<?php esc_attr_e( 'Close scan summary', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-no-alt" aria-hidden="true"></span></button>
						</header>
						<div class="abh-scan-summary-status <?php echo empty( $findings ) ? 'is-clean' : 'has-findings'; ?>">
							<span class="dashicons <?php echo empty( $findings ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
							<div>
						<strong><?php echo esc_html( empty( $findings ) ? __( 'Completed with no syntax errors', 'ai-bug-hunter' ) : sprintf( /* translators: %d: finding count requiring review. */ _n( '%d finding requires review', '%d findings require review', count( $findings ), 'ai-bug-hunter' ), count( $findings ) ) ); ?></strong>
								<span><?php esc_html_e( 'Saved summary of the last local scan.', 'ai-bug-hunter' ); ?></span>
							</div>
						</div>
						<dl class="abh-scan-summary-grid">
							<div><dt><?php esc_html_e( 'Date', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( $at ? wp_date( 'j M Y, H:i:s', $at ) : __( 'No date', 'ai-bug-hunter' ) ); ?></dd></div>
							<div><dt><?php esc_html_e( 'Duration', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( self::format_duration( $duration ) ); ?></dd></div>
							<div><dt><?php esc_html_e( 'Files reviewed', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( $scanned ) ); ?></dd></div>
							<div><dt><?php esc_html_e( 'Active findings', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( count( $findings ) ) ); ?></dd></div>
							<div><dt><?php esc_html_e( 'Scope', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( ! empty( $report['scope'] ) && 'full' === $report['scope'] ? __( 'Full WordPress', 'ai-bug-hunter' ) : __( 'Root, plugins and themes', 'ai-bug-hunter' ) ); ?></dd></div>
							<div><dt><?php esc_html_e( 'Identifier', 'ai-bug-hunter' ); ?></dt><dd><code><?php echo esc_html( ! empty( $report['scan_id'] ) ? $report['scan_id'] : __( 'Not available', 'ai-bug-hunter' ) ); ?></code></dd></div>
						</dl>
						<?php if ( ! empty( $findings ) ) : ?>
							<section class="abh-scan-summary-finding">
								<h3><?php esc_html_e( 'Main finding', 'ai-bug-hunter' ); ?></h3>
								<p><?php echo esc_html( ! empty( $findings[0]['short'] ) ? $findings[0]['short'] : ( ! empty( $findings[0]['message'] ) ? $findings[0]['message'] : __( 'Requires manual review.', 'ai-bug-hunter' ) ) ); ?></p>
							</section>
						<?php endif; ?>
						<footer>
							<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=' . ABH_SLUG . '-historial' ) ); ?>"><?php esc_html_e( 'Go to history', 'ai-bug-hunter' ); ?></a>
							<button type="button" class="button button-primary" data-abh-close-scan-summary><?php esc_html_e( 'Close', 'ai-bug-hunter' ); ?></button>
						</footer>
					</div>
				</div>
			<?php else : ?>
				<div class="abh-scan-result is-idle"><div class="abh-scan-result-main"><span class="dashicons dashicons-search"></span><div><strong><?php esc_html_e( 'No scan has been saved yet', 'ai-bug-hunter' ); ?></strong><span><?php esc_html_e( 'Run a scan to create the first snapshot of the code.', 'ai-bug-hunter' ); ?></span></div></div></div>
			<?php endif; ?>

			<?php $abh_wd_prominent = ABH_Watchdog::status(); ?>
			<?php if ( empty( $abh_wd_prominent['installed'] ) ) : ?>
				<div class="abh-watchdog-callout">
					<span class="dashicons dashicons-shield" aria-hidden="true"></span>
					<div>
						<strong><?php esc_html_e( 'Capture fatal errors that happen before WordPress can log them', 'ai-bug-hunter' ); ?></strong>
						<p><?php esc_html_e( 'Install the optional Watchdog once. It loads early, records the last fatal error locally, and never repairs or changes the failing code.', 'ai-bug-hunter' ); ?></p>
						<?php if ( ! empty( $abh_wd_prominent['writable'] ) ) : ?>
							<button type="button" class="button button-primary abh-watchdog-install"><?php esc_html_e( 'Install Watchdog', 'ai-bug-hunter' ); ?></button>
						<?php else : ?>
							<p class="abh-msg-warn"><?php esc_html_e( 'WordPress cannot write to the mu-plugins folder. Ask your hosting provider to adjust its permissions if you want to install Watchdog.', 'ai-bug-hunter' ); ?></p>
						<?php endif; ?>
						<div class="abh-watchdog-msg" aria-live="polite"></div>
					</div>
				</div>
			<?php endif; ?>

			<details class="abh-scan-tools" id="abh-scan-tools">
				<summary><?php esc_html_e( 'Tools and local scanner status', 'ai-bug-hunter' ); ?></summary>
				<div class="abh-scan-tools-grid">
					<?php
					$abh_riesgo = ABH_Core::version_risk();
					if ( ! empty( $abh_riesgo['vulnerable'] ) ) :
						?>
						<div class="abh-core-alert" role="alert"><strong><?php esc_html_e( 'Your WordPress version has a known critical vulnerability', 'ai-bug-hunter' ); ?></strong><p><?php echo esc_html( $abh_riesgo['message'] ); ?></p><a class="button button-primary" href="<?php echo esc_url( admin_url( 'update-core.php' ) ); ?>"><?php esc_html_e( 'Go to Updates', 'ai-bug-hunter' ); ?></a></div>
					<?php endif; ?>

					<?php $abh_wd = ABH_Watchdog::status(); $abh_wdr = ABH_Watchdog::records(); ?>
					<div class="abh-watchdog">
						<h3><?php esc_html_e( 'Fatal error watchdog', 'ai-bug-hunter' ); ?></h3>
						<?php if ( empty( $abh_wd['installed'] ) ) : ?>
							<p><?php esc_html_e( 'Records the fatal error that takes the site down even when WordPress does not get to write debug.log. It only observes and does not modify files.', 'ai-bug-hunter' ); ?></p>
							<?php if ( ! empty( $abh_wd['writable'] ) ) : ?><button type="button" class="button abh-watchdog-install"><?php esc_html_e( 'Install the watchdog', 'ai-bug-hunter' ); ?></button><?php else : ?><p class="abh-msg-warn"><?php esc_html_e( 'The mu-plugins folder does not allow writing from WordPress.', 'ai-bug-hunter' ); ?></p><?php endif; ?>
						<?php elseif ( ! empty( $abh_wd['partial'] ) ) : ?>
							<?php
							// Testigo NUESTRO que se quedó a medias. status() lo separa de
							// 'foreign' a propósito —un prefijo exacto de la plantilla no
							// puede ser de nadie más— y por eso aquí sí se ofrece
							// reescribirlo, mientras que la rama de archivo ajeno de más
							// abajo sigue sin ofrecer ningún control que lo pise.
							//
							// AVISO: esta vía de recuperación es un mejor esfuerzo, no un
							// sustituto del acceso al sistema de archivos. La plantilla
							// abre con unas sesenta líneas de comentario, así que la
							// mayoría de los cortes caen dentro del bloque y PHP muere con
							// «Unterminated comment» en TODAS las peticiones, este panel
							// incluido: entonces nadie llega a ver esta tarjeta y el
							// arreglo solo se puede hacer por FTP. Esta rama ayuda cuando
							// el corte cayó después del comentario y el escritorio aún
							// carga. Por eso el texto de abajo deja escrita también la
							// salida manual.
							?>
							<p class="abh-msg-warn" role="alert"><strong><?php esc_html_e( 'The watchdog file on disk is incomplete.', 'ai-bug-hunter' ); ?></strong></p>
							<p>
								<?php
								echo esc_html(
									sprintf(
										/* translators: %s: ruta relativa del testigo. */
										__( 'A write was left halfway through and %s was left truncated. That file runs on every request to your site, so while it stays this way parts of your site may fail to load.', 'ai-bug-hunter' ),
										$abh_wd['path']
									)
								);
								?>
							</p>
							<?php if ( ! empty( $abh_wd['writable'] ) ) : ?>
								<p><?php esc_html_e( 'Repairing writes the complete file over the truncated one and checks it byte by byte before leaving it in place.', 'ai-bug-hunter' ); ?></p>
								<button type="button" class="button button-primary abh-watchdog-install"><?php esc_html_e( 'Repair the watchdog', 'ai-bug-hunter' ); ?></button>
							<?php else : ?>
								<p class="abh-msg-warn"><?php esc_html_e( 'The mu-plugins folder does not allow writing from WordPress, so the file cannot be repaired from here.', 'ai-bug-hunter' ); ?></p>
							<?php endif; ?>
							<p class="abh-muted abh-small">
								<?php
								echo esc_html(
									sprintf(
										/* translators: %s: ruta relativa del testigo. */
										__( 'If your site stops loading before you get to use this, delete %s over FTP or from your hosting file manager: the site comes back without it, and you can install the watchdog again from here afterwards.', 'ai-bug-hunter' ),
										$abh_wd['path']
									)
								);
								?>
							</p>
							<button type="button" class="button-link abh-watchdog-uninstall"><?php esc_html_e( 'Remove the watchdog', 'ai-bug-hunter' ); ?></button>
						<?php elseif ( ! empty( $abh_wd['foreign'] ) ) : ?>
							<?php
							// Archivo de otra persona con nuestro mismo nombre. Aquí no se
							// pinta ningún control que escriba: ni reparar ni retirar.
							// install() y uninstall() también lo rechazan por su cuenta.
							?>
							<p class="abh-msg-warn"><?php esc_html_e( 'A file that is not ours already exists at the watchdog path. It will not be modified.', 'ai-bug-hunter' ); ?></p>
						<?php else : ?>
					<p class="abh-msg-ok"><?php echo esc_html( empty( $abh_wdr ) ? __( 'Installed and with no fatal errors logged.', 'ai-bug-hunter' ) : sprintf( /* translators: %d: recorded fatal error count. */ _n( '%d fatal error logged.', '%d fatal errors logged.', count( $abh_wdr ), 'ai-bug-hunter' ), count( $abh_wdr ) ) ); ?></p>
							<?php if ( ! empty( $abh_wdr ) ) : ?>
								<?php
								// Una cifra sola no sirve para nada: quien mira esto quiere
								// saber QUÉ archivo se cayó y en qué línea, que es justo lo
								// que el testigo anotó. El detalle ya viene saneado de dos
								// sitios —la plantilla recorta rutas absolutas y caracteres
								// de control al capturar, y records() revalida al leer—, así
								// que enseñarlo no expone nada nuevo.
								//
								// Se recorta a unas pocas entradas porque la opción admite
								// hasta veinte y esta tarjeta vive dentro del diagnóstico:
								// un sitio que cae en bucle no puede empujar el resto de la
								// pantalla fuera de la vista.
								$abh_wd_top   = array_slice( $abh_wdr, 0, 5 );
								$abh_wd_resto = count( $abh_wdr ) - count( $abh_wd_top );
								?>
								<ul class="abh-watchdog-list">
									<?php foreach ( $abh_wd_top as $abh_wd_r ) : ?>
										<li class="abh-watchdog-item">
											<code class="abh-path"><?php echo esc_html( '' !== $abh_wd_r['rel'] ? $abh_wd_r['rel'] : __( 'unidentified file', 'ai-bug-hunter' ) ); ?><?php echo $abh_wd_r['line'] ? esc_html( ':' . $abh_wd_r['line'] ) : ''; ?></code>
											<span class="abh-badge abh-badge-fatal"><?php echo esc_html( $abh_wd_r['kind'] ); ?></span>
											<?php if ( $abh_wd_r['count'] > 1 ) : ?>
												<span class="abh-count">×<?php echo esc_html( number_format_i18n( $abh_wd_r['count'] ) ); ?></span>
											<?php endif; ?>
											<p class="abh-msg"><?php echo esc_html( '' !== $abh_wd_r['msg'] ? $abh_wd_r['msg'] : __( 'PHP did not leave a message for this fatal error.', 'ai-bug-hunter' ) ); ?></p>
											<?php if ( $abh_wd_r['last'] > 0 ) : ?>
												<p class="abh-muted abh-small">
													<?php
													echo esc_html(
														sprintf(
															/* translators: %s: fecha y hora de la última vez que se vio el fatal. */
															__( 'Last seen: %s', 'ai-bug-hunter' ),
															wp_date( 'j M Y, H:i:s', $abh_wd_r['last'] )
														)
													);
													?>
												</p>
											<?php endif; ?>
										</li>
									<?php endforeach; ?>
								</ul>
								<?php if ( $abh_wd_resto > 0 ) : ?>
									<p class="abh-muted abh-small">
										<?php
										echo esc_html(
											sprintf(
												/* translators: %s: número de anotaciones que no se pintan. */
												_n(
													'%s older entry is stored and not shown here.',
													'%s older entries are stored and not shown here.',
													$abh_wd_resto,
													'ai-bug-hunter'
												),
												number_format_i18n( $abh_wd_resto )
											)
										);
										?>
									</p>
								<?php endif; ?>
							<?php endif; ?>
							<button type="button" class="button-link abh-watchdog-uninstall"><?php esc_html_e( 'Remove the watchdog', 'ai-bug-hunter' ); ?></button>
						<?php endif; ?>
						<div class="abh-watchdog-msg" aria-live="polite"></div>
					</div>

					<div class="abh-local-tool"><h3><?php esc_html_e( 'Core integrity', 'ai-bug-hunter' ); ?></h3><p><?php esc_html_e( 'Compares every WordPress file against the official fingerprint. It is deterministic and immediate.', 'ai-bug-hunter' ); ?></p><button type="button" class="button abh-core-scan"><?php esc_html_e( 'Check integrity', 'ai-bug-hunter' ); ?></button><div class="abh-core-result" aria-live="polite"></div></div>
					<?php self::render_estado_disco(); ?>
					<?php $abh_tot = ABH_Meter::totals(); ?>
					<div class="abh-meter-card"><h3><?php esc_html_e( 'Usage and savings', 'ai-bug-hunter' ); ?></h3><div class="abh-meter-grid"><div><span class="abh-meter-n"><?php echo esc_html( number_format_i18n( $abh_tot['consumed_total'] ) ); ?></span><?php esc_html_e( 'tokens used', 'ai-bug-hunter' ); ?></div><div><span class="abh-meter-n"><?php echo esc_html( number_format_i18n( $abh_tot['incidents'] ) ); ?></span><?php esc_html_e( 'incidents measured', 'ai-bug-hunter' ); ?></div><div class="is-gain"><span class="abh-meter-n"><?php echo esc_html( number_format_i18n( $abh_tot['avoided_total'] ) ); ?></span><?php esc_html_e( 'tokens avoided', 'ai-bug-hunter' ); ?></div></div></div>
				</div>
			</details>
		</section>
		<?php
	}
	/**
	 * Tarjeta de hallazgo del escáner sintáctico.
	 *
	 * @param array $finding Hallazgo.
	 * @return void
	 */
	private static function render_syntax_finding( $finding ) {
		$key  = isset( $finding['key'] ) ? (string) $finding['key'] : '';
		$rel  = isset( $finding['rel_path'] ) ? (string) $finding['rel_path'] : '';
		$line = isset( $finding['line'] ) ? (int) $finding['line'] : 0;
		$core = ! empty( $finding['core_file'] ) || ABH_Scanner::is_core_file( $rel );
		?>
		<div class="abh-card abh-incident abh-syntax-finding" data-key="<?php echo esc_attr( $key ); ?>">
			<div class="abh-inc-head">
				<span class="abh-badge abh-badge-fatal"><?php esc_html_e( 'SYNTAX', 'ai-bug-hunter' ); ?></span>
				<code class="abh-path"><?php echo esc_html( $rel . ( $line ? ':' . $line : '' ) ); ?></code>
				<?php if ( $core ) : ?><span class="abh-chip-protected"><?php esc_html_e( 'protected core', 'ai-bug-hunter' ); ?></span><?php endif; ?>
			</div>
			<p class="abh-msg"><?php echo esc_html( isset( $finding['short'] ) ? $finding['short'] : __( 'PHP cannot interpret this file.', 'ai-bug-hunter' ) ); ?></p>
			<?php if ( $core ) : ?>
				<div class="abh-protected">
					🔒 <strong><?php esc_html_e( 'HUNTER AI detected damage in a core file', 'ai-bug-hunter' ); ?></strong>
					<p><?php esc_html_e( 'The plugin will not modify this file automatically. The safe thing is to restore it from a clean copy of the same WordPress version or use Dashboard › Updates › Reinstall.', 'ai-bug-hunter' ); ?></p>
					<button class="button abh-advise" data-key="<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Explain how to restore it', 'ai-bug-hunter' ); ?></button>
				</div>
			<?php else : ?>
				<button class="button button-primary abh-analyze" data-key="<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Repair with HUNTER AI', 'ai-bug-hunter' ); ?></button>
				<button class="button abh-advise" data-key="<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Just explain it to me', 'ai-bug-hunter' ); ?></button>
			<?php endif; ?>
			<div class="abh-result" style="display:none"></div>
		</div>
		<?php
	}

	/**
	 * Controles de saneamiento del registro.
	 *
	 * Se pintan SIEMPRE y los primeros de la columna, antes de cualquier lista
	 * de incidencias. Son el remedio, y el remedio no puede depender de lo que
	 * haya en el registro: «Limpieza selectiva» vivía dentro del panel de
	 * historial, que sólo existe cuando ya hay algo resuelto u oculto, así que
	 * un registro inundado de incidencias activas —justo el caso que hay que
	 * poder arreglar— dejaba al operador sin el único botón que encoge el log
	 * conservando lo no revisado.
	 *
	 * Ninguno de los dos avisos de aquí usa la clase `.notice`: dashboard.js
	 * pliega en una bandeja todo `.notice` de la pantalla, y el aviso de
	 * recorte tiene que quedarse a la vista.
	 *
	 * @param int $omitidas Incidencias leídas que no se procesan ni se pintan.
	 * @param int $total    Incidencias leídas del registro.
	 * @return void
	 */
	private static function render_log_controls( $omitidas, $total ) {
		$omitidas = max( 0, (int) $omitidas );
		$total    = max( 0, (int) $total );
		?>
		<section class="abh-scan-card abh-log-controls">
			<div class="abh-scan-head">
				<div class="abh-scan-title">
					<div><h2><?php esc_html_e( 'PHP error log', 'ai-bug-hunter' ); ?></h2></div>
					<p><?php esc_html_e( 'Any visitor to your site can make PHP write to this log, so it grows on its own. These two controls shrink it and are always available here, no matter how long the list below gets.', 'ai-bug-hunter' ); ?></p>
				</div>
				<div class="abh-scan-actions">
					<button type="button" class="button abh-purge-resolved"><?php esc_html_e( 'Clean up only what is already resolved', 'ai-bug-hunter' ); ?></button>
					<button type="button" class="button abh-clear-log"><span class="dashicons dashicons-trash" aria-hidden="true"></span><?php esc_html_e( 'Clear log', 'ai-bug-hunter' ); ?></button>
				</div>
			</div>
			<?php if ( $omitidas > 0 ) : ?>
				<p class="abh-log-overflow abh-muted abh-small" role="status">
					<strong>
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: number of issues left out, 2: total number of issues read from the log. */
								_n(
									'%1$s of the %2$s issues read from the log is not shown on this screen.',
									'%1$s of the %2$s issues read from the log are not shown on this screen.',
									$omitidas,
									'ai-bug-hunter'
								),
								number_format_i18n( $omitidas ),
								number_format_i18n( $total )
							)
						);
						?>
					</strong>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: maximum number of issues rendered on the screen. */
							__( 'The list is capped at %s so that a log this large cannot make this page unusable. The entries left out are the least severe and least frequent ones.', 'ai-bug-hunter' ),
							number_format_i18n( self::MAX_INCIDENCIAS )
						)
					);
					?>
					<?php esc_html_e( 'Use "Clean up only what is already resolved" to shrink the log without losing anything you have not reviewed yet, or "Clear log" to empty it completely, and then reload this page.', 'ai-bug-hunter' ); ?>
				</p>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Pantalla principal.
	 *
	 * @return void
	 */
	public static function page_diagnostico() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'ai-bug-hunter' ) );
		}

		$scan          = ABH_Logs::scan();
		$activas       = array();
		$resueltas     = array();
		$informativas  = array();
		$ocultas       = 0;

		// El recorte se aplica ANTES de clasificar, no al pintar: la parte cara
		// de cada incidencia es la clasificación —respaldo aplicado, mtime,
		// estado de lint—, y dejarla sin techo permitía a un visitante sin
		// autenticar convertir esta pantalla en un tiempo de espera agotado sólo
		// escribiendo líneas en el log. Ver ABH_Admin::MAX_INCIDENCIAS.
		//
		// El corte va por delante porque ABH_Logs::parse() entrega la lista
		// ordenada de mayor a menor severidad y, a igual severidad, de más a
		// menos repeticiones: lo que se queda fuera es siempre lo menos grave.
		$leidas    = isset( $scan['incidents'] ) && is_array( $scan['incidents'] ) ? $scan['incidents'] : array();
		$total_inc = count( $leidas );
		$revisadas = array_slice( $leidas, 0, self::MAX_INCIDENCIAS );
		$omitidas  = $total_inc - count( $revisadas );

		foreach ( $revisadas as $inc ) {
			if ( ABH_Logs::is_dismissed( $inc ) ) {
				$ocultas++;
				continue;
			}
			$op   = ABH_Backup::last_applied_for( $inc['rel_path'], $inc['key'] );
			$hora = (int) $inc['last_unix'];

			if ( $op && ( 0 === $hora || ABH_Backup::op_unix( $op ) >= $hora ) ) {
				$inc['resuelta_por'] = $op;
				$inc['fecha_dudosa'] = ( 0 === $hora );
				$resueltas[]         = $inc;
			} elseif ( ABH_Motor::is_benign( $inc ) ) {
				$inc['informativa'] = true;
				$informativas[]     = $inc;
			} elseif ( ABH_Logs::syntax_already_fixed( $inc ) ) {
				$inc['intacta']  = true;
				$inc['por_lint'] = true;
				$resueltas[]     = $inc;
			} elseif ( ABH_Logs::is_intact( $inc ) ) {
				$inc['intacta'] = true;
				$resueltas[]    = $inc;
			} elseif ( ! empty( $inc['stale'] ) ) {
				$inc['obsoleta'] = true;
				$resueltas[]     = $inc;
			} else {
				$activas[] = $inc;
			}
		}

		$puente    = ABH_Bridge::findings();
		$dashboard = ABH_Dashboard::data( $activas, $resueltas, $informativas, $puente, $ocultas );
		$findings  = ABH_Dashboard::findings( $activas, $puente );
		?>
		<div class="wrap abh-wrap abh-diagnostic-page">
			<?php self::header( __( 'Summary', 'ai-bug-hunter' ), $dashboard ); ?>

			<div class="abh-diagnostic-layout">
				<main class="abh-diagnostic-main">
					<?php self::render_log_controls( $omitidas, $total_inc ); ?>
					<?php self::render_syntax_scan(); ?>
					<?php ABH_Dashboard::render_finding_workspace( $findings ); ?>

					<?php if ( ! empty( $scan['error'] ) ) : ?>
						<details class="abh-secondary-panel is-warning">
							<summary><span class="dashicons dashicons-warning"></span><?php esc_html_e( 'The PHP log needs attention', 'ai-bug-hunter' ); ?></summary>
							<div class="abh-secondary-body">
								<p><?php echo esc_html( $scan['error'] ); ?></p>
								<?php if ( ! empty( $scan['blocked'] ) ) : ?>
									<?php $log_info = ABH_Motor::inspect( $scan['blocked'][0] ); $log_fixable = ABH_Motor::env_fixable( $scan['blocked'][0] ); ?>
					<div class="abh-incident abh-environment-finding" data-key="log"><h3><?php esc_html_e( 'Insufficient permissions on the log', 'ai-bug-hunter' ); ?></h3><p><?php echo esc_html( sprintf( /* translators: 1: octal permissions, 2: file owner, 3: PHP process user. */ __( 'Permissions %1$s · owner %2$s · PHP runs as %3$s.', 'ai-bug-hunter' ), '' !== $log_info['perms'] ? $log_info['perms'] : __( 'unknown', 'ai-bug-hunter' ), '' !== $log_info['owner'] ? $log_info['owner'] : __( 'unknown', 'ai-bug-hunter' ), ABH_Motor::php_user() ) ); ?></p><?php if ( $log_fixable ) : ?><button class="button button-primary abh-env-fix" data-key="log"><?php esc_html_e( 'Review and fix in console', 'ai-bug-hunter' ); ?></button><?php else : ?><p class="abh-muted"><?php esc_html_e( 'Fix the permissions from your hosting or over SFTP. The plugin cannot change files that belong to another system user.', 'ai-bug-hunter' ); ?></p><?php endif; ?><div class="abh-result" style="display:none"></div></div>
								<?php else : ?>
									<?php self::render_debug_advice(); ?>
								<?php endif; ?>
							</div>
						</details>
					<?php endif; ?>

					<?php if ( ! empty( $resueltas ) || ! empty( $informativas ) || $ocultas > 0 ) : ?>
						<details class="abh-secondary-panel">
							<summary><span class="dashicons dashicons-archive"></span><?php esc_html_e( 'History and notices outside the main diagnosis', 'ai-bug-hunter' ); ?><span class="abh-secondary-count"><?php echo esc_html( number_format_i18n( count( $resueltas ) + count( $informativas ) + $ocultas ) ); ?></span></summary>
							<div class="abh-secondary-body">
					<?php // La limpieza selectiva ya no se duplica aquí: vive en render_log_controls(), fuera de este panel, porque este panel no llega a pintarse cuando todo lo que hay son incidencias activas. ?>
					<?php if ( $ocultas > 0 ) : ?><div class="abh-secondary-actions"><button type="button" class="button-link abh-undismiss"><?php echo esc_html( sprintf( /* translators: %d: hidden incident count. */ _n( 'Show %d hidden issue', 'Show %d hidden issues', $ocultas, 'ai-bug-hunter' ), $ocultas ) ); ?></button></div><?php endif; ?>
					<?php if ( ! empty( $resueltas ) ) : ?><h3><?php echo esc_html( sprintf( /* translators: %d: resolved incident count. */ _n( '%d issue resolved', '%d issues resolved', count( $resueltas ), 'ai-bug-hunter' ), count( $resueltas ) ) ); ?></h3><div class="abh-list abh-archive-list"><?php foreach ( $resueltas as $inc ) { self::render_incident( $inc, true ); } ?></div><?php endif; ?>
					<?php if ( ! empty( $informativas ) ) : ?><h3><?php echo esc_html( sprintf( /* translators: %d: informational notice count. */ _n( '%d informational notice', '%d informational notices', count( $informativas ), 'ai-bug-hunter' ), count( $informativas ) ) ); ?></h3>
								<p class="abh-muted abh-small"><?php esc_html_e( 'These are notices that do not depend on you: they are issued by other plugins or by the server itself, and they are not faults in your site. They are down here so they do not compete with what you do need to attend to.', 'ai-bug-hunter' ); ?></p><p class="abh-muted"><?php esc_html_e( 'They are not part of the pending items because they do not require modifying your site.', 'ai-bug-hunter' ); ?></p><div class="abh-list abh-archive-list"><?php foreach ( $informativas as $inc ) { self::render_incident( $inc, false ); } ?></div><?php endif; ?>
							</div>
						</details>
					<?php endif; ?>
				</main>

				<?php ABH_Dashboard::render_sidebar( $dashboard, $findings ); ?>
			</div>

			<?php ABH_Dashboard::render_statusbar( $dashboard ); ?>
		</div>
		<?php
	}
	/**
	 * Nombre legible del desenlace de una incidencia.
	 *
	 * @param string $outcome Desenlace del medidor.
	 * @return string
	 */
	private static function outcome_label( $outcome ) {
		$mapa = array(
			'repaired'      => __( 'repaired', 'ai-bug-hunter' ),
			'declined'      => __( 'rejected', 'ai-bug-hunter' ),
			'rolled_back'   => __( 'reverted', 'ai-bug-hunter' ),
			'deterministic' => __( 'resolved locally', 'ai-bug-hunter' ),
			'failed'        => __( 'unresolved', 'ai-bug-hunter' ),
			'inconclusive'  => __( 'inconclusive', 'ai-bug-hunter' ),
		);
		return isset( $mapa[ $outcome ] ) ? $mapa[ $outcome ] : '';
	}

	/**
	 * Dibuja la tarjeta de una incidencia.
	 *
	 * @param array $inc      Incidencia.
	 * @param bool  $resuelta Si ya fue corregida.
	 * @return void
	 */
	/**
	 * Instrucciones para activar el registro, sin repetir lo que ya existe.
	 *
	 * Este bloque vivía duplicado en dos sitios y en los dos imprimía las tres
	 * líneas define() pasara lo que pasara. Quien ya tenía alguna definida y las
	 * copiaba igualmente acababa con la constante repetida y un aviso de PHP por
	 * petición: la herramienta provocaba el fallo que después reportaba, y encima
	 * lo reportaba como incidencia bloqueada sin acción posible. Ahora hay un
	 * solo sitio, y comprueba antes de aconsejar.
	 *
	 * @return void
	 */
	/**
	 * Estado del disco.
	 *
	 * Todo lo reversible de este plugin se apoya en una copia guardada en disco.
	 * Si no hay espacio, no hay copia; y sin copia, la promesa de «se revierte en
	 * un clic» deja de ser cierta sin que nadie se entere. Por eso se enseña
	 * antes de que haga falta, no cuando ya falló.
	 *
	 * @return void
	 */
	private static function render_estado_disco() {
		if ( ! class_exists( 'ABH_Health' ) ) {
			return;
		}
		$disco = ABH_Health::disk();
		$ocupa = ABH_Health::ocupacion();
		$sitio = ABH_Health::room_for( 0 );
		$apuro = empty( $sitio['ok'] ) || ( $disco['total'] > 0 && $disco['usado_pct'] >= 95 );
		?>
		<div class="abh-disco <?php echo $apuro ? 'is-apuro' : ''; ?>">
			<p class="abh-disco-linea">
				<strong><?php esc_html_e( 'Backup space', 'ai-bug-hunter' ); ?></strong>
				<?php if ( $disco['total'] > 0 ) : ?>
					<span><?php
						echo esc_html( sprintf(
							/* translators: 1: libre, 2: total, 3: porcentaje usado. */
							__( '%1$s free of %2$s · %3$s%% used', 'ai-bug-hunter' ),
							size_format( $disco['libre'], 1 ),
							size_format( $disco['total'], 1 ),
							$disco['usado_pct']
						) );
					?></span>
				<?php else : ?>
					<span class="abh-muted"><?php esc_html_e( 'Your hosting does not allow checking free space. Backups will still be made; if the disk fills up, the repair will stop before touching anything.', 'ai-bug-hunter' ); ?></span>
				<?php endif; ?>
			</p>
			<?php if ( $ocupa['transacciones'] > 0 ) : ?>
				<p class="abh-disco-linea">
					<span><?php
						echo esc_html( sprintf(
							/* translators: 1: número de reparaciones, 2: tamaño. */
							_n( '%1$d repair saved for rollback · %2$s', '%1$d repairs saved for rollback · %2$s', $ocupa['transacciones'], 'ai-bug-hunter' ),
							$ocupa['transacciones'],
							size_format( $ocupa['bytes'], 1 )
						) );
					?></span>
					<button type="button" class="button-link abh-disco-limpiar"><?php esc_html_e( 'Free up the ones that can no longer be reverted', 'ai-bug-hunter' ); ?></button>
				</p>
			<?php endif; ?>
			<?php if ( $apuro ) : ?>
				<p class="abh-msg-warn"><?php
					echo esc_html( ! empty( $sitio['message'] )
						? $sitio['message']
						: __( 'The disk is almost full. Before repairing anything, HUNTER AI checks that the backup fits: if it does not fit, it stops and does not touch the site.', 'ai-bug-hunter' ) );
				?></p>
			<?php endif; ?>
			<div class="abh-disco-msg" aria-live="polite"></div>
		</div>
		<?php
	}

	private static function render_debug_advice() {
		$consejo = ABH_Logs::debug_config_advice();
		?>
		<?php if ( ! empty( $consejo['add'] ) ) : ?>
			<p><?php esc_html_e( 'To enable the error log, add these lines to wp-config.php just before the line «That\'s all, stop editing»:', 'ai-bug-hunter' ); ?></p>
			<pre class="abh-code"><?php
			$lineas = array();
			foreach ( $consejo['add'] as $nombre => $valor ) {
				$lineas[] = "define( '" . $nombre . "', " . $valor . ' );';
			}
			echo esc_html( implode( "\n", $lineas ) );
			?></pre>
		<?php endif; ?>

		<?php if ( ! empty( $consejo['change'] ) ) : ?>
			<p>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: lista de constantes. */
						_n(
							'Warning: %s is already defined in wp-config.php, but its value does not enable logging. CHANGE that line; do not add another one below it.',
							'Warning: %s are already defined in wp-config.php, but their values do not enable logging. CHANGE those lines; do not add more below them.',
							count( $consejo['change'] ),
							'ai-bug-hunter'
						),
						implode( ', ', array_keys( $consejo['change'] ) )
					)
				);
				?>
			</p>
			<pre class="abh-code"><?php
			$cambios = array();
			foreach ( $consejo['change'] as $nombre => $valor ) {
				$cambios[] = "define( '" . $nombre . "', " . $valor . ' );';
			}
			echo esc_html( implode( "\n", $cambios ) );
			?></pre>
			<p class="abh-muted"><?php esc_html_e( 'If you define the same constant twice, PHP keeps the first one, ignores the second and records a notice on every visit. The site keeps working, but the log fills up with noise.', 'ai-bug-hunter' ); ?></p>
		<?php endif; ?>

		<?php if ( ! empty( $consejo['ok'] ) ) : ?>
			<p class="abh-muted"><?php esc_html_e( 'The log constants are already set correctly. If the file still does not appear, the problem is the permissions or the path, not wp-config.php.', 'ai-bug-hunter' ); ?></p>
		<?php else : ?>
			<p class="abh-muted"><?php esc_html_e( 'You make this change yourself: the plugin never writes to wp-config.php. Make a copy of the file before editing it.', 'ai-bug-hunter' ); ?></p>
		<?php endif; ?>
		<?php
	}

	private static function render_incident( $inc, $resuelta ) {
		$fatal = $inc['severity'] >= 90;
		$check = '' !== $inc['rel_path']
			? ABH_Guard::check_path( $inc['rel_path'], ABH_Engine::writable_roots() )
			: array(
				'allowed'  => false,
				'findings' => array(),
			);
		$prot = ( '' !== $inc['rel_path'] && ! $check['allowed'] );
		$info = ( $prot && ! empty( $check['findings'] ) ) ? ABH_Guard::describe( $check['findings'][0] ) : null;
		// Bloqueado pero sin hallazgo que citar: no se deja a null, porque más
		// abajo la plantilla lee su código y su explicación.
		if ( $prot && ! is_array( $info ) ) {
			$info = array(
				'code'        => 'BH-SEC-000',
				'titulo'      => __( 'Protected path', 'ai-bug-hunter' ),
				'explicacion' => __( 'This path is outside what HUNTER AI can write to.', 'ai-bug-hunter' ),
			);
		}
		if ( is_array( $info ) && ! isset( $info['code'] ) ) {
			$info['code'] = '';
		}

		// Capa 0: HUNTER AI local. Cuesta cero y responde al instante.
		$motor = ABH_Motor::diagnose( $inc );
		?>
		<div class="abh-card abh-incident <?php echo $resuelta ? 'abh-is-solved' : ''; ?>" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
			<div class="abh-inc-head">
				<?php if ( $resuelta ) : ?>
					<?php if ( ! empty( $inc['intacta'] ) ) : ?>
						<span class="abh-badge abh-badge-old" title="<?php esc_attr_e( 'The file matches its published original byte for byte and compiles without errors.', 'ai-bug-hunter' ); ?>"><?php esc_html_e( 'FILE INTACT', 'ai-bug-hunter' ); ?></span>
					<?php elseif ( ! empty( $inc['obsoleta'] ) ) : ?>
						<span class="abh-badge abh-badge-old" title="<?php esc_attr_e( 'The file changed after the last time this error appeared.', 'ai-bug-hunter' ); ?>"><?php esc_html_e( 'HISTORICAL', 'ai-bug-hunter' ); ?></span>
					<?php else : ?>
						<span class="abh-badge abh-badge-solved"><?php esc_html_e( 'RESOLVED', 'ai-bug-hunter' ); ?></span>
					<?php endif; ?>
				<?php else : ?>
					<span class="abh-badge <?php echo $fatal ? 'abh-badge-fatal' : 'abh-badge-warn'; ?>">
						<?php echo esc_html( $fatal ? __( 'FATAL', 'ai-bug-hunter' ) : __( 'notice', 'ai-bug-hunter' ) ); ?>
					</span>
				<?php endif; ?>
				<?php if ( $inc['count'] > 1 ) : ?>
					<span class="abh-count">×<?php echo (int) $inc['count']; ?></span>
				<?php endif; ?>
				<code class="abh-path">
					<?php echo esc_html( '' !== $inc['rel_path'] ? $inc['rel_path'] : __( 'unidentified file', 'ai-bug-hunter' ) ); ?><?php echo $inc['line'] ? esc_html( ':' . $inc['line'] ) : ''; ?>
				</code>
				<?php if ( ! $resuelta ) : ?>
					<button type="button" class="button-link abh-dismiss" data-key="<?php echo esc_attr( $inc['key'] ); ?>" title="<?php esc_attr_e( 'Hide this issue. It will reappear on its own if the error happens again.', 'ai-bug-hunter' ); ?>">
						<?php esc_html_e( 'hide', 'ai-bug-hunter' ); ?>
					</button>
				<?php endif; ?>
			</div>

			<p class="abh-msg"><?php echo esc_html( $inc['short'] ); ?></p>

			<?php if ( $resuelta ) : ?>
				<?php
				// Una incidencia llega aquí por dos caminos distintos: porque una
				// operación del historial la reparó, o porque el archivo cambió
				// después de la última vez que el error apareció (obsoleta). En
				// el segundo caso no hay operación que citar, y leerla a ciegas
				// era lo que generaba los avisos de este mismo archivo.
				$op = isset( $inc['resuelta_por'] ) && is_array( $inc['resuelta_por'] ) ? $inc['resuelta_por'] : null;
				?>
				<p class="abh-solved-note">
					<?php if ( $op ) : ?>
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: fecha, 2: quién lo corrigió. */
								__( 'Fixed on %1$s by %2$s. These lines are from the log before the fix; if the error happens again, the issue will reappear at the top on its own.', 'ai-bug-hunter' ),
								isset( $op['ts'] ) ? $op['ts'] : __( 'unknown date', 'ai-bug-hunter' ),
								( isset( $op['model'] ) && ABH_Motor::SIGNATURE === $op['model'] )
									? __( 'Local HUNTER AI', 'ai-bug-hunter' )
									: ( ! empty( $op['model'] ) ? ABH_Privacy::mask_if_secret( (string) $op['model'] ) : __( 'an earlier operation', 'ai-bug-hunter' ) )
							)
						);
						?>
					<?php elseif ( ! empty( $inc['intacta'] ) ) : ?>
						<?php
						// La pregunta que hace todo el mundo al ver esto es «pero si
						// esa línea está bien, ¿por qué me lo marca?». Se contesta
						// aquí, sin que haga falta abrir la consola.
							esc_html_e( 'Checked: this file matches the plugin developer\'s published original byte for byte, and the PHP compiler accepts it. AI Bug Hunter does not propose a modification because there is no evidence that this file is damaged. Changing verified upstream code could override intentional behavior and introduce larger regressions.', 'ai-bug-hunter' );
						?>
						<br>
						<em>
							<?php
							echo esc_html(
								$inc['line']
									? sprintf(
										/* translators: %d: línea. */
										__( 'Why it kept showing up: the error log is a historical record and nobody rewrites old entries. Line %d identifies where PHP stopped during that request, but it does not prove that the currently deployed file should be changed. If the error happens again, the issue will reappear above for a new review.', 'ai-bug-hunter' ),
										(int) $inc['line']
									)
									: __( 'Why it kept showing up: the error log is a historical record and nobody rewrites old entries. It does not prove that the currently deployed file should be changed. If the error happens again, the issue will reappear above for a new review.', 'ai-bug-hunter' )
							);
							?>
						</em>
					<?php elseif ( ! empty( $inc['obsoleta'] ) ) : ?>
						<?php esc_html_e( 'Historical: the file was modified after the last time this error appeared, so these lines are from the past. There is nothing to repair. If the error happens again, the issue will reappear above on its own.', 'ai-bug-hunter' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'It is no longer pending. These lines are from the previous log; if the error happens again, the issue will reappear above on its own.', 'ai-bug-hunter' ); ?>
					<?php endif; ?>
					<?php if ( ! empty( $inc['fecha_dudosa'] ) ) : ?>
						<br><em><?php esc_html_e( 'Note: the date of these log lines could not be read, so the comparison was made by file only. If the error keeps happening, it will show up at the top again as soon as the log writes a readable date.', 'ai-bug-hunter' ); ?></em>
					<?php endif; ?>
				</p>

			<?php elseif ( $motor ) : ?>
				<div class="abh-motor">
					<div class="abh-motor-head">
						<span class="abh-chip-motor"><?php esc_html_e( 'HUNTER AI · local engine', 'ai-bug-hunter' ); ?></span>
						<strong><?php echo esc_html( $motor['code'] . ' — ' . $motor['titulo'] ); ?></strong>
					</div>
					<p class="abh-motor-diag"><?php echo esc_html( $motor['diagnosis'] ); ?></p>
					<?php if ( ! empty( $motor['steps'] ) ) : ?>
						<ol class="abh-motor-steps">
							<?php foreach ( $motor['steps'] as $paso ) : ?>
								<li><?php echo esc_html( $paso ); ?></li>
							<?php endforeach; ?>
						</ol>
					<?php endif; ?>
					<?php $abh_sin_acciones = ! empty( $inc['informativa'] ) && empty( $motor['culpable'] ); ?>
					<div class="abh-actions"<?php echo $abh_sin_acciones ? ' style="display:none"' : ''; ?>>
						<?php if ( ! empty( $inc['informativa'] ) ) : ?>
							<?php
							// Aquí no hay nada que reparar ni que preguntarle a un
							// modelo: el diagnóstico ya nombra al culpable y el
							// culpable no es este sitio. Ofrecer «revisar con la IA»
							// sería invitar a gastar tokens en algo ya resuelto.
								// Tampoco se repite un botón de ocultar: la cabecera de
								// la tarjeta ya lleva el suyo. Lo que sí falta aquí es
								// decir de dónde viene, que es el dato que se calcula y
								// hasta ahora no se enseñaba en ninguna parte.
								?>
								<?php if ( ! empty( $motor['culpable'] ) ) : ?>
									<span class="abh-culpable">
										<?php esc_html_e( 'Comes from:', 'ai-bug-hunter' ); ?>
										<code><?php echo esc_html( $motor['culpable'] ); ?></code>
									</span>
								<?php endif; ?>
						<?php else : ?>
						<?php if ( ! empty( $motor['fixable'] ) ) : ?>
							<button class="button button-primary abh-env-fix" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
								<?php esc_html_e( 'Review and fix in console', 'ai-bug-hunter' ); ?>
							</button>
						<?php endif; ?>
						<?php if ( ! $prot ) : ?>
							<button class="button abh-analyze" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
								<?php esc_html_e( 'Review with HUNTER AI', 'ai-bug-hunter' ); ?>
							</button>
						<?php else : ?>
							<button class="button abh-advise" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
								<?php esc_html_e( 'Ask the AI', 'ai-bug-hunter' ); ?>
							</button>
						<?php endif; ?>
						<?php endif; ?>
					</div>
				</div>

			<?php elseif ( $prot ) : ?>
				<?php $nucleo = ( 'BH-SEC-003' === $info['code'] ) ? ABH_Core::file_status( $inc['rel_path'] ) : array( 'is_core' => false ); ?>
				<div class="abh-protected">
					🔒 <strong><?php echo esc_html( $info['code'] . ' — ' . $info['titulo'] ); ?></strong>
					<p><?php echo esc_html( $info['explicacion'] ); ?></p>

					<?php if ( ! empty( $nucleo['is_core'] ) ) : ?>
						<?php
						// La solución vive aquí mismo. Obligar a bajar hasta el
						// escáner de integridad para descubrirla era un callejón
						// sin salida para quien no sabe que ese escáner existe.
						?>
						<?php $abh_fn = ABH_Core::undefined_function_in( $inc['short'] ); ?>
						<div class="abh-core-file abh-core-inline" data-file="<?php echo esc_attr( $inc['rel_path'] ); ?>" data-fn="<?php echo esc_attr( $abh_fn ); ?>">
							<p class="abh-core-inline-lead">
								<?php if ( ! empty( $nucleo['accepted'] ) ) : ?>
									<?php esc_html_e( 'You marked this change as intentional. You can view it again or undo it.', 'ai-bug-hunter' ); ?>
								<?php elseif ( ! empty( $nucleo['altered'] ) ) : ?>
									<?php esc_html_e( 'Confirmed: this file does not match the WordPress original. I can show you exactly what changed and put it back the way it was.', 'ai-bug-hunter' ); ?>
								<?php elseif ( ! empty( $nucleo['missing'] ) ) : ?>
									<?php esc_html_e( 'This core file is missing from your installation. I can put it back with the verified original.', 'ai-bug-hunter' ); ?>
								<?php elseif ( ! empty( $nucleo['known'] ) ) : ?>
									<?php esc_html_e( 'This file is an original WordPress file and it is intact: it is not the one failing, it is only where the failure shows. The cause is in another file and I can locate it.', 'ai-bug-hunter' ); ?>
								<?php else : ?>
									<?php esc_html_e( 'It belongs to WordPress core. I can compare it with the official original right now.', 'ai-bug-hunter' ); ?>
								<?php endif; ?>
							</p>
							<?php
							// Si el archivo está intacto, comparar no aporta nada: lo
							// útil es rastrear qué archivo debería definir la función.
							// Ese pasa a ser el botón principal.
							$abh_rastreo = ( '' !== $abh_fn && ! empty( $nucleo['known'] ) && empty( $nucleo['altered'] ) && empty( $nucleo['missing'] ) );
							?>
							<span class="abh-core-actions">
								<?php if ( '' !== $abh_fn ) : ?>
									<?php
									// El error nombra al archivo que LLAMA a la función, no al
									// que debería definirla. Casi siempre el roto es el segundo.
									?>
									<button type="button" class="button <?php echo $abh_rastreo ? 'button-primary' : ''; ?> abh-core-blame" data-fn="<?php echo esc_attr( $abh_fn ); ?>">
										<?php esc_html_e( 'Where is the cause?', 'ai-bug-hunter' ); ?>
									</button>
								<?php endif; ?>
								<button type="button" class="button <?php echo $abh_rastreo ? '' : 'button-primary'; ?> abh-core-diff">
									<?php esc_html_e( 'Compare with the WordPress original', 'ai-bug-hunter' ); ?>
								</button>
								<button type="button" class="button-link abh-core-restore"><?php esc_html_e( 'Restore official', 'ai-bug-hunter' ); ?></button>
								<button type="button" class="button-link abh-advise" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
									<?php esc_html_e( 'Tell me how to fix it myself', 'ai-bug-hunter' ); ?>
								</button>
							</span>
							<div class="abh-core-diffbox"></div>
						</div>
					<?php else : ?>
						<?php
						// Decir «protegido» y callarse deja al cliente sin saber
						// qué se está evitando. El radio de daño es determinista:
						// se puede decir exactamente qué pasaría y si tendría
						// vuelta atrás, sin tocar el archivo ni una vez.
						$abh_radio = class_exists( 'ABH_Lab' ) ? ABH_Lab::blast_radius( $inc['rel_path'] ) : null;
						?>
						<?php if ( is_array( $abh_radio ) ) : ?>
							<details class="abh-blast">
								<summary><?php esc_html_e( 'Why does it not touch it, and what would happen if it did?', 'ai-bug-hunter' ); ?></summary>
								<p><strong><?php esc_html_e( 'What it affects:', 'ai-bug-hunter' ); ?></strong> <?php echo esc_html( $abh_radio['scope'] ); ?></p>
								<p><strong><?php esc_html_e( 'If the change goes wrong:', 'ai-bug-hunter' ); ?></strong> <?php echo esc_html( $abh_radio['consequence'] ); ?></p>
								<p><strong><?php esc_html_e( 'How it is recovered:', 'ai-bug-hunter' ); ?></strong> <?php echo esc_html( $abh_radio['recovery'] ); ?></p>
								<?php if ( empty( $abh_radio['recoverable'] ) ) : ?>
									<p class="abh-muted"><?php esc_html_e( 'That is the exact reason for the ban: it is not that the change is difficult, it is that if it goes wrong there is no screen left from which to fix it.', 'ai-bug-hunter' ); ?></p>
								<?php endif; ?>
							</details>
						<?php endif; ?>
						<button class="button abh-advise" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
							<?php esc_html_e( 'Tell me how to fix it myself', 'ai-bug-hunter' ); ?>
						</button>
					<?php endif; ?>
				</div>

			<?php else : ?>
				<button class="button button-primary abh-analyze" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
					<?php esc_html_e( 'Repair with HUNTER AI', 'ai-bug-hunter' ); ?>
				</button>
				<button class="button abh-advise" data-key="<?php echo esc_attr( $inc['key'] ); ?>">
					<?php esc_html_e( 'Just explain it to me', 'ai-bug-hunter' ); ?>
				</button>
			<?php endif; ?>

			<div class="abh-result" style="display:none"></div>
		</div>
		<?php
	}

	/**
	 * Historial de cambios.
	 *
	 * @return void
	 */
	public static function page_historial() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'ai-bug-hunter' ) );
		}
		$journal = ABH_Backup::journal();
		?>
		<div class="wrap abh-wrap">
			<?php self::header( __( 'Change history', 'ai-bug-hunter' ) ); ?>

			<?php if ( empty( $journal ) ) : ?>
				<div class="abh-card abh-empty">
					<p><?php esc_html_e( 'No change has been applied yet.', 'ai-bug-hunter' ); ?></p>
				</div>
			<?php else : ?>
				<table class="widefat abh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Date', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'File', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Diagnosis', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Status', 'ai-bug-hunter' ); ?></th>
							<th></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $journal as $op ) : ?>
						<tr>
							<td><?php echo esc_html( $op['ts'] ); ?></td>
							<td><code><?php echo esc_html( $op['rel_path'] ); ?></code>
								<div class="abh-muted abh-small"><?php echo esc_html( ABH_Privacy::mask_if_secret( (string) $op['model'] ) ); ?></div>
							</td>
							<td>
								<?php if ( ! empty( $op['action'] ) && 'core_restore' === $op['action'] ) : ?>
									<span class="abh-tag-core" title="<?php esc_attr_e( 'WordPress core file returned to its official content, verified by MD5 fingerprint.', 'ai-bug-hunter' ); ?>"><?php esc_html_e( 'core', 'ai-bug-hunter' ); ?></span>
								<?php endif; ?>
								<?php if ( ! empty( $op['explicacion']['tipo'] ) && 'sintoma' === $op['explicacion']['tipo'] ) : ?>
									<span class="abh-tag-sintoma" title="<?php esc_attr_e( 'This change silenced the notice but did not remove the underlying cause.', 'ai-bug-hunter' ); ?>"><?php esc_html_e( 'symptom only', 'ai-bug-hunter' ); ?></span>
								<?php endif; ?>
								<?php echo esc_html( $op['diagnosis'] ); ?>
								<?php if ( ! empty( $op['explicacion']['que_no'] ) ) : ?>
									<div class="abh-muted abh-small"><?php echo esc_html( __( 'It does not fix:', 'ai-bug-hunter' ) . ' ' . $op['explicacion']['que_no'] ); ?></div>
								<?php endif; ?>
								<?php
								// Medidor único: el Historial lee el MISMO libro mayor que la
								// consola y el reporte, para que las tres cifras no puedan
								// discrepar. Si la operación es anterior al medidor, se cae al
								// consumo que guardó la propia operación.
								$medidor = ! empty( $op['incident_key'] ) ? ABH_Meter::snapshot( $op['incident_key'] ) : null;
								if ( $medidor && 0 === $medidor['total'] && 0 === $medidor['avoided_total'] ) {
									$medidor = null;
								}
								if ( $medidor ) :
									?>
									<div class="abh-muted abh-small abh-op-meter">
										<?php if ( $medidor['total'] > 0 ) : ?>
											<span class="abh-op-meter-n">
											<?php
											echo esc_html(
												sprintf(
													/* translators: 1: tokens de entrada, 2: tokens de salida. */
													__( '%1$s + %2$s tokens', 'ai-bug-hunter' ),
													number_format_i18n( $medidor['usage']['in'] ),
													number_format_i18n( $medidor['usage']['out'] )
												) . ( '' !== $medidor['cost'] ? ' · ' . $medidor['cost'] : '' )
											);
											?>
											</span>
										<?php endif; ?>
										<?php if ( $medidor['avoided_total'] > 0 ) : ?>
											<span class="abh-op-meter-gain">
												<?php
												echo esc_html(
													sprintf(
														/* translators: %s: tokens ahorrados. */
														__( 'no model · %s tokens saved', 'ai-bug-hunter' ),
														number_format_i18n( $medidor['avoided_total'] )
													)
												);
												?>
											</span>
										<?php endif; ?>
										<?php if ( $medidor['settled'] ) : ?>
											<span class="abh-op-meter-out"><?php echo esc_html( self::outcome_label( $medidor['outcome'] ) ); ?></span>
										<?php endif; ?>
									</div>
								<?php elseif ( ! empty( $op['usage']['in'] ) || ! empty( $op['usage']['out'] ) ) :
									$coste = ABH_Router::cost_label( $op['usage'] );
									?>
									<div class="abh-muted abh-small">
										<?php
										echo esc_html(
											sprintf(
												/* translators: 1: tokens de entrada, 2: tokens de salida. */
												__( '%1$d + %2$d tokens', 'ai-bug-hunter' ),
												isset( $op['usage']['in'] ) ? (int) $op['usage']['in'] : 0,
												isset( $op['usage']['out'] ) ? (int) $op['usage']['out'] : 0
											) . ( '' !== $coste ? ' · ' . $coste : '' )
										);
										?>
									</div>
								<?php endif; ?>
							</td>
							<td>
								<?php if ( 'applied' === $op['status'] ) : ?>
									<span class="abh-state abh-state-ok"><?php esc_html_e( 'applied', 'ai-bug-hunter' ); ?></span>
								<?php elseif ( 'partial' === $op['status'] ) : ?>
									<?php
									// Una vuelta atrás incompleta NO es «revertido». Decirlo
									// así haría que el dueño dejara de mirar justo cuando hay
									// archivos tocados esperándole.
									?>
									<span class="abh-state abh-state-warn"><?php esc_html_e( 'partial', 'ai-bug-hunter' ); ?></span>
								<?php elseif ( 'failed' === $op['status'] ) : ?>
									<?php
									// Un intento fallido tampoco es «revertido»: puede haber
									// dejado el archivo a medio escribir, y el propio motor le
									// pide al dueño que revierta desde el Historial de
									// inmediato. Etiquetarlo de revertido le quitaba el aviso
									// y el botón a la vez.
									?>
									<span class="abh-state abh-state-warn"><?php esc_html_e( 'failed', 'ai-bug-hunter' ); ?></span>
								<?php else : ?>
									<span class="abh-state abh-state-back"><?php esc_html_e( 'reverted', 'ai-bug-hunter' ); ?></span>
								<?php endif; ?>
							</td>
							<td>
								<?php if ( 'applied' === $op['status'] ) : ?>
									<button class="button abh-rollback" data-op="<?php echo esc_attr( $op['op_id'] ); ?>">
										<?php esc_html_e( 'Revert', 'ai-bug-hunter' ); ?>
									</button>
								<?php elseif ( 'partial' === $op['status'] ) : ?>
									<button class="button abh-rollback" data-op="<?php echo esc_attr( $op['op_id'] ); ?>">
										<?php esc_html_e( 'Retry the revert', 'ai-bug-hunter' ); ?>
									</button>
								<?php elseif ( 'failed' === $op['status'] ) : ?>
									<?php
									// Un fallo puede dejar el archivo a medio escribir, así que
									// aquí hace más falta el botón que en ningún otro estado.
									?>
									<button class="button abh-rollback" data-op="<?php echo esc_attr( $op['op_id'] ); ?>">
										<?php esc_html_e( 'Revert', 'ai-bug-hunter' ); ?>
									</button>
								<?php endif; ?>
								<button class="button abh-history-bundle" data-op="<?php echo esc_attr( ! empty( $op['txn_id'] ) ? $op['txn_id'] : $op['op_id'] ); ?>" title="<?php esc_attr_e( 'Download report, console log and diff in a single ZIP', 'ai-bug-hunter' ); ?>">
									<?php esc_html_e( 'Download case file', 'ai-bug-hunter' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Catálogo público de códigos de bloqueo.
	 *
	 * @return void
	 */
	public static function page_seguridad() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'ai-bug-hunter' ) );
		}
		?>
		<div class="wrap abh-wrap">
			<?php self::header( __( 'Security', 'ai-bug-hunter' ) ); ?>

			<div class="abh-card">
				<h2><?php esc_html_e( 'How it protects you', 'ai-bug-hunter' ); ?></h2>
				<ol class="abh-gates">
					<li><strong><?php esc_html_e( 'Untouchable files.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'wp-config.php, .htaccess and the WordPress core are never written to. Advice only.', 'ai-bug-hunter' ); ?></li>
					<li><strong><?php esc_html_e( 'Change review.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'Only what the fix adds is analyzed, not the code you already had.', 'ai-bug-hunter' ); ?></li>
					<li><strong><?php esc_html_e( 'Syntax check.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'If the fix does not compile, it is not written.', 'ai-bug-hunter' ); ?></li>
					<li><strong><?php esc_html_e( 'Your approval.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'You see the before and the after, line by line, before anything is touched.', 'ai-bug-hunter' ); ?></li>
					<li><strong><?php esc_html_e( 'Backup and revert.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'The original is saved and, if the site gets worse, it reverts on its own.', 'ai-bug-hunter' ); ?></li>
				</ol>
			</div>

			<div class="abh-card">
				<h2><?php esc_html_e( 'Local HUNTER AI: immediate diagnostics', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'Many errors in the log are not code faults but faults in the server environment. The engine recognizes them, checks the real state of the file system and gives you the diagnosis instantly.', 'ai-bug-hunter' ); ?></p>
				<table class="widefat abh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Code', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Detects', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Why this cannot be fixed with code', 'ai-bug-hunter' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( ABH_Motor::catalog() as $code => $info ) : ?>
						<tr>
							<td><code><?php echo esc_html( $code ); ?></code></td>
							<td><strong><?php echo esc_html( $info['titulo'] ); ?></strong></td>
							<td><?php echo esc_html( $info['explicacion'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p class="abh-muted">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: usuario del sistema con el que corre PHP. */
							__( 'On this server, PHP runs as «%s».', 'ai-bug-hunter' ),
							ABH_Motor::php_user()
						)
					);
					?>
				</p>
			</div>

			<div class="abh-card abh-limits">
				<h2><?php esc_html_e( 'What the WordPress.org edition can analyze and export', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'This table comes from the public edition policy. Diagnosis and export remain available, while proposed repairs are never applied by this plugin.', 'ai-bug-hunter' ); ?></p>
				<table class="widefat abh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Operation', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'How far it goes', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Does it ask for permission?', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Can it be undone?', 'ai-bug-hunter' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( ABH_Limits::operations() as $abh_op ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $abh_op['titulo'] ); ?></strong>
								<div class="abh-muted abh-small"><?php echo esc_html( $abh_op['porque'] ); ?></div>
							</td>
							<td><?php echo esc_html( $abh_op['alcance'] ); ?></td>
							<td><?php echo esc_html( $abh_op['consiente'] ); ?></td>
							<td><?php echo esc_html( $abh_op['revertir'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>

				<h3><?php esc_html_e( 'What it does not do, no matter what', 'ai-bug-hunter' ); ?></h3>
				<ul class="abh-limits-never">
					<?php foreach ( ABH_Limits::will_not() as $abh_n ) : ?>
						<li><?php echo esc_html( $abh_n ); ?></li>
					<?php endforeach; ?>
				</ul>

				<h3><?php esc_html_e( 'Whose responsibility it is', 'ai-bug-hunter' ); ?></h3>
				<ul class="abh-limits-resp">
					<?php foreach ( ABH_Limits::responsibility() as $abh_r ) : ?>
						<li><?php echo esc_html( $abh_r ); ?></li>
					<?php endforeach; ?>
				</ul>
			</div>

			<div class="abh-card">
				<h2><?php esc_html_e( 'Proposal validation codes', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'These codes explain why a path or proposed difference cannot be presented safely.', 'ai-bug-hunter' ); ?></p>
				<table class="widefat abh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Code', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Reason', 'ai-bug-hunter' ); ?></th>
							<th><?php esc_html_e( 'Explanation', 'ai-bug-hunter' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( ABH_Guard::catalog() as $code => $info ) : ?>
						<tr>
							<td><code><?php echo esc_html( $code ); ?></code></td>
							<td><strong><?php echo esc_html( $info['titulo'] ); ?></strong></td>
							<td><?php echo esc_html( $info['explicacion'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Ajustes.
	 *
	 * @return void
	 */
	public static function page_ajustes() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'ai-bug-hunter' ) );
		}
		$s = ABH_Router::settings();
		?>
		<div class="wrap abh-wrap">
			<?php self::header( __( 'Settings', 'ai-bug-hunter' ) ); ?>

			<form method="post" class="abh-card">
				<?php wp_nonce_field( 'abh_save_settings', 'abh_settings_nonce' ); ?>

				<h2><?php esc_html_e( 'Your AI model', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'It uses your own key. Before sending them, the plugin redacts detectable secrets and personal data. The stored key is encrypted and is only sent to the confirmed provider.', 'ai-bug-hunter' ); ?></p>

				<div class="abh-mistral-setup">
					<div class="abh-mistral-setup-head">
						<span class="dashicons dashicons-admin-network" aria-hidden="true"></span>
						<div>
							<strong><?php esc_html_e( 'No credits with another AI provider? Start with Mistral.', 'ai-bug-hunter' ); ?></strong>
							<p><?php esc_html_e( 'You can create a Mistral account and use its Free mode to get started. Mistral applies its own usage and rate limits, which may change. You can also choose OpenAI, Anthropic, or any other supported provider below.', 'ai-bug-hunter' ); ?></p>
						</div>
					</div>
					<ol>
						<li><a href="https://console.mistral.ai/?profile_dialog=api-keys" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Create or open your Mistral API keys', 'ai-bug-hunter' ); ?></a>.</li>
						<li><?php esc_html_e( 'Create a new key, copy it immediately, and paste it into the API key field below.', 'ai-bug-hunter' ); ?></li>
						<li><?php esc_html_e( 'Select “Mistral API” as the provider and use one of these model identifiers:', 'ai-bug-hunter' ); ?>
							<div class="abh-mistral-models"><code>mistral-small-2603</code><span><?php esc_html_e( 'recommended', 'ai-bug-hunter' ); ?></span><code>mistral-small-2506</code><span><?php esc_html_e( 'compatible fallback', 'ai-bug-hunter' ); ?></span></div>
						</li>
						<li><?php esc_html_e( 'The native Mistral provider configures its endpoint automatically. If you use the OpenAI-compatible provider instead, the custom base URL is:', 'ai-bug-hunter' ); ?>
							<div class="abh-mistral-base"><code>https://api.mistral.ai/v1</code><button type="button" class="button abh-copy-value" data-copy-value="https://api.mistral.ai/v1"><?php esc_html_e( 'Copy URL', 'ai-bug-hunter' ); ?></button></div>
						</li>
					</ol>
					<p class="abh-actions"><button type="button" class="button button-primary abh-use-mistral-settings"><?php esc_html_e( 'Use recommended Mistral settings', 'ai-bug-hunter' ); ?></button><span class="abh-copy-status" role="status" aria-live="polite"></span></p>
				</div>
				<div class="notice notice-info inline">
					<p><strong><?php esc_html_e( 'External service and consent', 'ai-bug-hunter' ); ?></strong></p>
					<p><?php esc_html_e( 'If you authorize it, the selected provider will receive excerpts from the related file, error messages, relative paths, technical evidence, and instructions. The purpose is to analyze the incident and generate an explanation or reviewable proposal.', 'ai-bug-hunter' ); ?></p>
					<p><?php esc_html_e( 'Before transmission, the plugin attempts to redact detectable keys, tokens, email addresses, and IP addresses. Redaction reduces risk but does not guarantee complete anonymity. The provider may retain or process data under its terms.', 'ai-bug-hunter' ); ?></p>
					<p>
						<a href="https://openai.com/policies/privacy-policy/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'OpenAI privacy', 'ai-bug-hunter' ); ?></a> ·
						<a href="https://openai.com/policies/business-terms/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'OpenAI terms', 'ai-bug-hunter' ); ?></a> ·
						<a href="https://www.anthropic.com/legal/privacy" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Anthropic privacy', 'ai-bug-hunter' ); ?></a> ·
						<a href="https://www.anthropic.com/legal/commercial-terms" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Anthropic terms', 'ai-bug-hunter' ); ?></a> ·
						<a href="https://legal.mistral.ai/terms/privacy-policy" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Mistral privacy', 'ai-bug-hunter' ); ?></a> ·
						<a href="https://legal.mistral.ai/terms/commercial-terms-of-service" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Mistral terms', 'ai-bug-hunter' ); ?></a>
					</p>
					<p><?php esc_html_e( 'For a custom compatible server, the privacy policy and terms of the operator you specify apply.', 'ai-bug-hunter' ); ?></p>
					<p><label for="abh_external_service_consent"><input type="checkbox" name="abh_external_service_consent" id="abh_external_service_consent" value="1" <?php checked( ! empty( $s['external_service_consent'] ) ); ?>> <strong><?php esc_html_e( 'I expressly authorize the communications described for the selected provider. I can withdraw authorization by clearing this checkbox and saving.', 'ai-bug-hunter' ); ?></strong></label></p>
				</div>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="abh_provider"><?php esc_html_e( 'Provider', 'ai-bug-hunter' ); ?></label></th>
						<td>
							<select name="abh_provider" id="abh_provider">
								<option value=""><?php esc_html_e( '— Choose —', 'ai-bug-hunter' ); ?></option>
								<?php foreach ( ABH_Router::providers() as $abh_pid => $abh_p ) : ?>
									<option value="<?php echo esc_attr( $abh_pid ); ?>"
										<?php selected( $s['provider'], $abh_pid ); ?>
										<?php disabled( empty( $abh_p['available'] ) ); ?>
										data-nota="<?php echo esc_attr( $abh_p['nota'] ); ?>"
										data-key="<?php echo esc_attr( ! empty( $abh_p['needs_key'] ) ? '1' : '0' ); ?>"
										data-billed="<?php echo esc_attr( $abh_p['billed_to'] ); ?>">
										<?php
										echo esc_html( $abh_p['label'] );
										if ( empty( $abh_p['available'] ) ) {
											echo esc_html( ' — ' . __( 'not yet available on this installation', 'ai-bug-hunter' ) );
										}
										?>
									</option>
								<?php endforeach; ?>
							</select>
							<?php
							// El aviso de consumo se pinta aquí y lo rellena el
							// navegador: nadie debería descubrir que un cambio le
							// cuesta dinero DESPUÉS de haberlo hecho.
							?>
							<div class="abh-provider-note" aria-live="polite"></div>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="abh_model"><?php esc_html_e( 'Model', 'ai-bug-hunter' ); ?></label></th>
						<td>
							<?php $abh_model_leak = ! empty( $s['model_is_secret'] ); ?>
							<input type="text" name="abh_model" id="abh_model" class="regular-text" value="<?php echo $abh_model_leak ? '' : esc_attr( $s['model'] ); ?>" placeholder="gpt-5.6-luna">
							<?php if ( $abh_model_leak ) : ?>
								<p class="description abh-danger"><strong><?php esc_html_e( 'The value saved here has the shape of an API key and is not printed again on this page.', 'ai-bug-hunter' ); ?></strong> <?php esc_html_e( 'Revoke it in your provider\'s dashboard and type the model name here. The credential goes in “API key”.', 'ai-bug-hunter' ); ?></p>
							<?php endif; ?>
							<p class="description"><?php esc_html_e( 'The exact model identifier, just as your provider names it.', 'ai-bug-hunter' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="abh_api_key"><?php esc_html_e( 'API key', 'ai-bug-hunter' ); ?></label></th>
						<td>
							<input type="password" name="abh_api_key" id="abh_api_key" class="regular-text" value="" autocomplete="new-password" placeholder="<?php echo $s['api_key'] ? esc_attr__( '•••••••• (configured — leave it blank to keep it)', 'ai-bug-hunter' ) : ''; ?>" <?php disabled( 'constant' === $s['key_source'] ); ?>>
							<?php if ( 'constant' === $s['key_source'] ) : ?>
								<p class="description"><?php esc_html_e( 'The key comes from the ABH_API_KEY constant and is not stored in the database.', 'ai-bug-hunter' ); ?></p>
							<?php else : ?>
								<p class="description"><?php esc_html_e( 'If you enter a new key it is encrypted before being saved. Leave it empty to keep the current one.', 'ai-bug-hunter' ); ?></p>
								<?php if ( 'encrypted_option' === $s['key_source'] ) : ?>
									<label><input type="checkbox" name="abh_clear_api_key" value="1"> <?php esc_html_e( 'Delete the saved key.', 'ai-bug-hunter' ); ?></label>
								<?php endif; ?>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="abh_base_url"><?php esc_html_e( 'Custom base URL', 'ai-bug-hunter' ); ?></label></th>
						<td>
							<input type="url" name="abh_base_url" id="abh_base_url" class="regular-text" value="<?php echo esc_attr( $s['base_url'] ); ?>" placeholder="http://127.0.0.1:11434/v1">
							<p class="description"><?php esc_html_e( 'Only for an OpenAI-compatible server. Public endpoints require HTTPS; localhost or a private IP requires additional authorization.', 'ai-bug-hunter' ); ?></p>
							<p><label><input type="checkbox" name="abh_endpoint_confirmed" id="abh_endpoint_confirmed" value="1" <?php checked( ! empty( $s['custom_endpoint_confirmed'] ) ); ?>> <?php esc_html_e( 'I confirm that this URL will receive redacted code fragments and logs, and that the key belongs to that server.', 'ai-bug-hunter' ); ?></label></p>
							<p><label><input type="checkbox" name="abh_allow_private" id="abh_allow_private" value="1" <?php checked( ! empty( $s['allow_private_endpoint'] ) ); ?>> <?php esc_html_e( 'Explicitly authorize localhost or a literal private IP for a local model.', 'ai-bug-hunter' ); ?></label></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="abh_price_in"><?php esc_html_e( 'Price per million tokens', 'ai-bug-hunter' ); ?></label></th>
						<td>
							<label for="abh_price_in"><?php esc_html_e( 'Input', 'ai-bug-hunter' ); ?>
								<input type="text" name="abh_price_in" id="abh_price_in" class="small-text" value="<?php echo esc_attr( ! empty( $s['price_in'] ) ? $s['price_in'] : '' ); ?>" placeholder="0.15">
							</label>
							&nbsp;&nbsp;
							<label for="abh_price_out"><?php esc_html_e( 'Output', 'ai-bug-hunter' ); ?>
								<input type="text" name="abh_price_out" id="abh_price_out" class="small-text" value="<?php echo esc_attr( ! empty( $s['price_out'] ) ? $s['price_out'] : '' ); ?>" placeholder="0.60">
							</label>
							<p class="description"><?php esc_html_e( 'Optional, in dollars, exactly as your provider publishes them. If you fill them in, each query will tell you roughly how much it cost. If you leave them empty, only the tokens are shown.', 'ai-bug-hunter' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'On uninstall', 'ai-bug-hunter' ); ?></th>
						<td>
							<label for="abh_wipe">
								<input type="checkbox" name="abh_wipe" id="abh_wipe" value="1" <?php checked( ! empty( $s['wipe_on_uninstall'] ) ); ?>>
								<?php esc_html_e( 'Also delete settings, history and backups when the plugin is removed.', 'ai-bug-hunter' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Keys and pending proposals are always deleted on uninstall. This checkbox only controls the full cleanup of the history, non-secret settings and backups.', 'ai-bug-hunter' ); ?></p>
						</td>
					</tr>
				</table>

				<p>
					<?php submit_button( __( 'Save settings', 'ai-bug-hunter' ), 'primary', 'submit', false ); ?>
					<button type="button" class="button abh-test"><?php esc_html_e( 'Test connection', 'ai-bug-hunter' ); ?></button>
					<span class="abh-test-result"></span>
				</p>
			</form>

			<div class="abh-card">
				<h2><?php esc_html_e( 'Error log', 'ai-bug-hunter' ); ?></h2>
				<?php $log = ABH_Logs::find_log(); ?>
				<?php if ( $log ) : ?>
					<p>✅ <?php echo esc_html( sprintf( /* translators: %s: ruta. */ __( 'Log active at: %s', 'ai-bug-hunter' ), $log ) ); ?></p>
				<?php else : ?>
					<p>⚠️ <?php esc_html_e( 'There is no active error log.', 'ai-bug-hunter' ); ?></p>
					<?php self::render_debug_advice(); ?>
				<?php endif; ?>
			</div>

			<div class="abh-card">
				<h2><?php esc_html_e( 'Maintenance', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'Deletes the saved backups and empties the history. It does not affect your site.', 'ai-bug-hunter' ); ?></p>
				<button type="button" class="button abh-purge"><?php esc_html_e( 'Delete backups and history', 'ai-bug-hunter' ); ?></button>
			</div>
		</div>
		<?php
	}


	/**
	 * Pantalla de apoyo.
	 *
	 * Pide dinero una sola vez y sin rehenes: todo lo que el plugin sabe hacer
	 * ya está disponible antes de entrar aquí, y sigue estándolo si nadie paga
	 * nunca. Lo único que se muestra son números que ya ocurrieron.
	 *
	 * @return void
	 */
	public static function page_apoyo() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'ai-bug-hunter' ) );
		}

		$destinos = ABH_Support::destinos();
		$merito   = ABH_Support::merito();
		$estado   = ABH_Support::state();
		?>
		<div class="wrap abh-wrap">
			<?php self::header( __( 'Support', 'ai-bug-hunter' ) ); ?>

			<div class="abh-card abh-ok">
				<h2><?php esc_html_e( 'This WordPress.org edition is free and will always remain free.', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted">
					<?php esc_html_e( 'Your support helps us keep it maintained, secure, tested, and compatible with future WordPress releases. Donations fund security audits, bug hunting, compatibility testing, AI credits, and continued development.', 'ai-bug-hunter' ); ?>
				</p>
				<p class="abh-muted">
					<?php esc_html_e( 'The Pro edition is a separate product with AI-assisted autofix. The WordPress.org edition remains analysis-only for externally generated repairs and will continue providing diagnostics, proposed diffs, and clear repair guidance.', 'ai-bug-hunter' ); ?>
				</p>
			</div>

			<?php if ( $merito['reparaciones'] > 0 ) : ?>
				<div class="abh-card">
					<h2><?php esc_html_e( 'What you have saved on this site so far', 'ai-bug-hunter' ); ?></h2>
					<div class="abh-apoyo-cifras">
						<div class="abh-apoyo-cifra">
							<b><?php echo esc_html( number_format_i18n( $merito['reparaciones'] ) ); ?></b>
							<span><?php esc_html_e( 'repairs resolved without calling any model', 'ai-bug-hunter' ); ?></span>
						</div>
						<div class="abh-apoyo-cifra">
							<b><?php echo esc_html( number_format_i18n( $merito['tokens'] ) ); ?></b>
							<span><?php esc_html_e( 'tokens that were not sent to anyone', 'ai-bug-hunter' ); ?></span>
						</div>
						<?php if ( '' !== $merito['costo'] ) : ?>
							<div class="abh-apoyo-cifra">
								<b><?php echo esc_html( $merito['costo'] ); ?></b>
								<span><?php esc_html_e( 'that you would have paid with your provider', 'ai-bug-hunter' ); ?></span>
							</div>
						<?php endif; ?>
					</div>
					<p class="abh-muted abh-small">
						<?php esc_html_e( 'It comes from this installation\'s meter ledger, not from a brochure estimate. It only counts the issues that a deterministic engine closed with zero calls.', 'ai-bug-hunter' ); ?>
					</p>
				</div>
			<?php else : ?>
				<div class="abh-card abh-empty">
					<h2><?php esc_html_e( 'It has not saved you anything measurable yet', 'ai-bug-hunter' ); ?></h2>
					<p class="abh-muted"><?php esc_html_e( 'No repair on this site has been resolved without a model yet. When that happens, the number will appear here on its own. Supporting before that is fine too, but we prefer to tell you.', 'ai-bug-hunter' ); ?></p>
				</div>
			<?php endif; ?>

			<div class="abh-card abh-feedback-card" data-feedback-email="<?php echo esc_attr( ABH_Support::feedback_email() ); ?>">
				<span class="abh-apoyo-etq"><?php esc_html_e( 'Help improve AI Bug Hunter', 'ai-bug-hunter' ); ?></span>
				<h2><?php esc_html_e( 'Report a bug or request a feature', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'Choose what you want to share. The matching form will appear below. Reporting and feature requests are free and do not require a donation.', 'ai-bug-hunter' ); ?></p>
				<div class="abh-feedback-choices" role="group" aria-label="<?php esc_attr_e( 'Choose feedback type', 'ai-bug-hunter' ); ?>">
					<button type="button" class="button abh-feedback-choice" data-feedback-type="bug" aria-pressed="false"><?php esc_html_e( 'Report a bug', 'ai-bug-hunter' ); ?></button>
					<button type="button" class="button abh-feedback-choice" data-feedback-type="feature" aria-pressed="false"><?php esc_html_e( 'Request a feature', 'ai-bug-hunter' ); ?></button>
				</div>
				<form class="abh-feedback-form" hidden>
					<input type="hidden" class="abh-feedback-type" value="">
					<h3 class="abh-feedback-form-title"></h3>
					<div class="abh-feedback-grid">
						<label>
							<span><?php esc_html_e( 'Short title', 'ai-bug-hunter' ); ?></span>
							<input type="text" class="regular-text abh-feedback-title" maxlength="120" required>
						</label>
						<label class="abh-feedback-wide">
							<span class="abh-feedback-description-label"><?php esc_html_e( 'What happened?', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-description" rows="5" maxlength="2000" required></textarea>
						</label>
						<label class="abh-feedback-bug-only abh-feedback-wide">
							<span><?php esc_html_e( 'Steps to reproduce', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-steps" rows="4" maxlength="1500"></textarea>
						</label>
						<label class="abh-feedback-bug-only">
							<span><?php esc_html_e( 'What did you expect?', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-expected" rows="4" maxlength="1000"></textarea>
						</label>
						<label class="abh-feedback-feature-only">
							<span><?php esc_html_e( 'How should it work?', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-workflow" rows="4" maxlength="1500"></textarea>
						</label>
						<label class="abh-feedback-feature-only abh-feedback-wide">
							<span><?php esc_html_e( 'Who would benefit and why?', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-benefit" rows="3" maxlength="1000"></textarea>
						</label>
						<label class="abh-feedback-wide">
							<span><?php esc_html_e( 'Optional technical details', 'ai-bug-hunter' ); ?></span>
							<textarea class="large-text abh-feedback-technical" rows="3" maxlength="1200" placeholder="<?php esc_attr_e( 'WordPress version, PHP version, plugin version, or other context you choose to share', 'ai-bug-hunter' ); ?>"></textarea>
						</label>
					</div>
					<p class="abh-muted abh-small"><?php esc_html_e( 'Nothing is collected or sent automatically. You can copy the report or open it as a draft in your own email application, review it, and decide whether to send it.', 'ai-bug-hunter' ); ?></p>
					<p class="abh-actions">
						<button type="button" class="button abh-feedback-copy"><?php esc_html_e( 'Copy report', 'ai-bug-hunter' ); ?></button>
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Open email draft', 'ai-bug-hunter' ); ?></button>
						<span class="abh-feedback-status" role="status" aria-live="polite"></span>
					</p>
				</form>
			</div>

			<?php if ( ! empty( $destinos ) ) : ?>
				<div class="abh-apoyo-grid">

					<?php if ( isset( $destinos['anual'] ) ) : ?>
						<div class="abh-apoyo-card abh-apoyo-destacada">
							<span class="abh-apoyo-etq"><?php esc_html_e( 'Annual support', 'ai-bug-hunter' ); ?></span>
							<div class="abh-apoyo-monto">
								<b><?php echo esc_html( '$' . number_format_i18n( ABH_Support::ANUAL_USD ) ); ?></b>
								<span><?php esc_html_e( 'USD per year', 'ai-bug-hunter' ); ?></span>
							</div>
							<p><?php esc_html_e( 'Become an annual supporter and receive early access to the separate Pro edition, including AI-assisted autofix. Your contribution helps fund security audits, bug hunting, compatibility testing, AI credits, and continued development.', 'ai-bug-hunter' ); ?></p>
							<p class="abh-small abh-muted"><?php esc_html_e( 'Early access is delivered separately. It does not add autofix or external code application to this WordPress.org package.', 'ai-bug-hunter' ); ?></p>
							<a class="button button-primary" href="<?php echo esc_url( $destinos['anual'] ); ?>" target="_blank" rel="noopener noreferrer">
								<?php
								echo esc_html(
									sprintf(
										/* translators: %s: monto en dólares. */
										__( 'Support annually with PayPal · %s', 'ai-bug-hunter' ),
										'$' . number_format_i18n( ABH_Support::ANUAL_USD )
									)
								);
								?>
							</a>
						</div>
					<?php endif; ?>

					<?php if ( isset( $destinos['donacion'] ) ) : ?>
						<div class="abh-apoyo-card">
							<span class="abh-apoyo-etq"><?php esc_html_e( 'One-off donation', 'ai-bug-hunter' ); ?></span>
							<div class="abh-apoyo-monto">
								<b><?php echo esc_html( '$' . number_format_i18n( ABH_Support::MINIMO_USD ) ); ?></b>
								<span><?php esc_html_e( 'USD one time', 'ai-bug-hunter' ); ?></span>
							</div>
							<p><?php esc_html_e( 'Make a one-time $5 contribution to help keep the free WordPress.org edition alive, maintained, and updated. Every contribution helps us test more cases and improve the project for the community.', 'ai-bug-hunter' ); ?></p>
							<p class="abh-small abh-muted"><?php esc_html_e( 'No subscription and no reminders.', 'ai-bug-hunter' ); ?></p>
							<a class="button" href="<?php echo esc_url( $destinos['donacion'] ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Donate $5 with PayPal', 'ai-bug-hunter' ); ?>
							</a>
						</div>
					<?php endif; ?>

					<?php if ( isset( $destinos['regalo'] ) ) : ?>
						<div class="abh-apoyo-card abh-apoyo-baller">
							<span class="abh-apoyo-etq"><?php esc_html_e( 'BIG BALLER', 'ai-bug-hunter' ); ?></span>
							<div class="abh-apoyo-monto">
								<b><?php esc_html_e( 'Support', 'ai-bug-hunter' ); ?></b>
								<span><?php esc_html_e( 'the developers!', 'ai-bug-hunter' ); ?></span>
							</div>
							<p><?php esc_html_e( 'We currently fund this project ourselves. As the community grows, we need more resources for security audits, bug hunting, compatibility testing, AI credits, and the development of new features.', 'ai-bug-hunter' ); ?></p>
							<p><?php esc_html_e( 'If life is treating you well and you would like to help us grow, your support can give us more time to build useful tools for the community.', 'ai-bug-hunter' ); ?></p>
							<p class="abh-gift-instruction"><?php esc_html_e( 'When an official gifting option is available in your Claude or ChatGPT account, enter this recipient email:', 'ai-bug-hunter' ); ?></p>
							<div class="abh-gift-email">
								<code><?php echo esc_html( $destinos['regalo'] ); ?></code>
								<button type="button" class="button abh-copy-value" data-copy-value="<?php echo esc_attr( $destinos['regalo'] ); ?>"><?php esc_html_e( 'Copy recipient email', 'ai-bug-hunter' ); ?></button>
							</div>
							<p class="abh-small abh-muted"><?php esc_html_e( 'Gift availability depends on the provider, account, and region. Only continue when the provider shows an official gifting option. The plugin never sees gift details or payment information.', 'ai-bug-hunter' ); ?></p>
							<div class="abh-gift-actions">
								<a class="button" href="https://claude.ai/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open Claude', 'ai-bug-hunter' ); ?></a>
								<a class="button" href="https://chatgpt.com/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open ChatGPT', 'ai-bug-hunter' ); ?></a>
							</div>
							<span class="abh-copy-status" role="status" aria-live="polite"></span>
						</div>
					<?php endif; ?>

				</div>
			<?php else : ?>
				<div class="abh-card abh-empty">
					<h2><?php esc_html_e( 'There is nowhere to send you', 'ai-bug-hunter' ); ?></h2>
					<p class="abh-muted"><?php esc_html_e( 'The support destinations are empty in this installation, so no button is drawn. A button that leads nowhere is worse than no button at all.', 'ai-bug-hunter' ); ?></p>
				</div>
			<?php endif; ?>

			<div class="abh-card abh-giveaway-card">
				<span class="abh-apoyo-etq"><?php esc_html_e( 'Community giveaway', 'ai-bug-hunter' ); ?></span>
				<h2><?php esc_html_e( 'Your support helps launch a giveaway of 10 Pro licenses.', 'ai-bug-hunter' ); ?></h2>
				<p class="abh-muted"><?php esc_html_e( 'As support grows, we give more back to the community. Eligibility, dates, a free method of entry, and the complete official rules will be published on our website before the giveaway opens.', 'ai-bug-hunter' ); ?></p>
				<p class="abh-muted abh-small"><?php esc_html_e( 'A donation alone does not create an entry until the official rules and entry period are available.', 'ai-bug-hunter' ); ?></p>
				<a class="button" href="https://aibughunter.com/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Visit our official website and see more of our work', 'ai-bug-hunter' ); ?></a>
			</div>

			<div class="abh-card">
				<h2><?php esc_html_e( 'This page', 'ai-bug-hunter' ); ?></h2>
				<?php if ( 'apoyo' === $estado['estado'] ) : ?>
					<p class="abh-msg-ok"><?php esc_html_e( 'You already marked that you supported. Thank you, really.', 'ai-bug-hunter' ); ?></p>
					<p class="abh-muted abh-small"><?php esc_html_e( 'It is a local flag to stop asking you. The plugin cannot verify payments, and it does not try: it does not talk to any server of ours.', 'ai-bug-hunter' ); ?></p>
				<?php elseif ( 'nunca' === $estado['estado'] ) : ?>
					<p class="abh-muted"><?php esc_html_e( 'You asked not to see the notice again. That is respected; this page stays here in case you change your mind.', 'ai-bug-hunter' ); ?></p>
				<?php else : ?>
					<form method="post">
						<?php wp_nonce_field( 'abh_support', 'abh_support_nonce' ); ?>
						<p class="abh-muted"><?php esc_html_e( 'If you already supported the project, or if you would rather it was not mentioned again, say so here and the notice disappears.', 'ai-bug-hunter' ); ?></p>
						<p class="abh-actions">
							<button type="submit" name="abh_support_action" value="apoye" class="button"><?php esc_html_e( 'I already supported', 'ai-bug-hunter' ); ?></button>
							<button type="submit" name="abh_support_action" value="despues" class="button"><?php esc_html_e( 'After', 'ai-bug-hunter' ); ?></button>
							<button type="submit" name="abh_support_action" value="nunca" class="button-link abh-dismiss"><?php esc_html_e( 'Do not show me this again', 'ai-bug-hunter' ); ?></button>
						</p>
					</form>
				<?php endif; ?>
				<p class="abh-muted abh-small">
					<?php esc_html_e( 'Payment and gift details are never requested inside WordPress. Payment buttons open the provider in another tab. Feedback remains in your browser until you choose to copy it or open a draft in your own email application; the plugin never sends it automatically.', 'ai-bug-hunter' ); ?>
				</p>
			</div>
		</div>
		<?php
	}
}
