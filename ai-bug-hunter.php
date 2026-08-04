<?php
/**
 * Plugin Name:       AI Bug Hunter
 * Plugin URI:        https://bughunter.digital
 * Description:       Analyze PHP errors with optional AI, review proposed diffs, and follow manual repair guidance. This edition never applies externally generated code.
 * Version:           1.0
 * Requires at least: 6.3.5
 * Requires PHP:      7.4
 * Author:            AI Bug Hunter
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ai-bug-hunter
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'ABH_FILE' ) ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'AI Bug Hunter and AI Bug Hunter Pro are alternative editions and cannot be active at the same time.', 'ai-bug-hunter' ) . '</p></div>';
			}
		}
	);
	return;
}

define( 'ABH_VERSION', '1.0' );
define( 'ABH_FILE', __FILE__ );
define( 'ABH_DIR', plugin_dir_path( __FILE__ ) );
define( 'ABH_URL', plugin_dir_url( __FILE__ ) );
define( 'ABH_SLUG', 'ai-bug-hunter' );
define( 'ABH_ASSET_VERSION', ABH_VERSION . '.' . (string) filemtime( ABH_DIR . 'assets/admin.js' ) );

// La marca, en un solo sitio. Cambiar el nombre del motor es cambiar esta línea
// y nada más: ninguna pantalla lo escribe a mano.
define( 'ABH_PRODUCT_NAME', 'AI Bug Hunter' );
define( 'ABH_ENGINE_NAME', 'HUNTER AI' );
define( 'ABH_MASCOT_NAME', 'Hunter' );

require_once ABH_DIR . 'includes/class-abh-edition.php';
require_once ABH_DIR . 'includes/class-abh-crypto.php';
require_once ABH_DIR . 'includes/class-abh-privacy.php';
require_once ABH_DIR . 'includes/class-abh-public-policy.php';
require_once ABH_DIR . 'includes/class-abh-logs.php';
require_once ABH_DIR . 'includes/class-abh-scanner.php';
require_once ABH_DIR . 'includes/class-abh-motor.php';
require_once ABH_DIR . 'includes/class-abh-bridge.php';
require_once ABH_DIR . 'includes/class-abh-verifier.php';
require_once ABH_DIR . 'includes/class-abh-backup.php';
require_once ABH_DIR . 'includes/class-abh-meter.php';
require_once ABH_DIR . 'includes/class-abh-report.php';
require_once ABH_DIR . 'includes/class-abh-support.php';
require_once ABH_DIR . 'includes/class-abh-router.php';
require_once ABH_DIR . 'includes/class-abh-ai-connection.php';
require_once ABH_DIR . 'includes/class-abh-engine.php';
require_once ABH_DIR . 'includes/class-abh-root.php';
require_once ABH_DIR . 'includes/class-abh-health.php';
require_once ABH_DIR . 'includes/class-abh-structured-fixer.php';
require_once ABH_DIR . 'includes/class-abh-artifacts.php';
require_once ABH_DIR . 'includes/class-abh-evidence.php';
require_once ABH_DIR . 'includes/class-abh-contract.php';
require_once ABH_DIR . 'includes/class-abh-thoth-ai.php';
require_once ABH_DIR . 'includes/class-abh-chat.php';
require_once ABH_DIR . 'includes/class-abh-core.php';
require_once ABH_DIR . 'includes/class-abh-cve.php';
require_once ABH_DIR . 'includes/class-abh-source.php';
require_once ABH_DIR . 'includes/class-abh-damage.php';
require_once ABH_DIR . 'includes/class-abh-lab.php';
require_once ABH_DIR . 'includes/class-abh-watchdog.php';
require_once ABH_DIR . 'includes/class-abh-dashboard.php';
require_once ABH_DIR . 'includes/class-abh-admin.php';
require_once ABH_DIR . 'includes/class-abh-ajax.php';

/**
 * Arranque del plugin.
 */
function abh_init() {
	// Migración alpha63: el aviso root de bienvenida ya no existe. Limpiamos
	// sus opciones heredadas una vez al actualizar para que ninguna versión
	// anterior, caché de objetos o reactivación pueda volver a levantarlo.
	if ( ABH_VERSION !== get_option( 'abh_version_vista', '' ) ) {
		update_option( 'abh_version_vista', ABH_VERSION, false );
		delete_option( 'abh_bienvenida_pendiente' );
		delete_option( 'abh_bienvenida_leida' );
	}
	ABH_Admin::init();
	ABH_Ajax::init();
	// Pide apoyo una sola vez, y solo después de haber hecho méritos.
	ABH_Support::init();
	// Alimenta la tabla de vulnerabilidades del núcleo por su propio filtro.
	ABH_CVE::init();
}
add_action( 'plugins_loaded', 'abh_init' );

/**
 * Activación: deja los ajustes por defecto y nada más.
 *
 * ACTIVAR NO TOCA EL DISCO. El almacén de respaldos se crea y se blinda solo
 * cuando hay de verdad algo que guardar —ABH_Backup::snapshot(), la caché del
 * núcleo, el laboratorio—, que son los que llaman a prepare_storage(). Crear
 * carpetas porque alguien pulsó «Activar» es escribir en el sitio sin que nadie
 * lo haya pedido, y en la mayoría de instalaciones ese almacén no se usa nunca.
 */
function abh_activate() {
	// Una instalación o reactivación nunca debe bloquear el escritorio con una
	// aceptación root. La firma se solicita desde la consola únicamente cuando
	// el plan concreto contiene operaciones que requieren ese privilegio.
	delete_option( 'abh_bienvenida_pendiente' );
	delete_option( 'abh_bienvenida_leida' );
	add_option(
		'abh_settings',
		array(
			'provider'   => '',
			'model'      => '',
			'base_url'   => '',
			'custom_endpoint_confirmed' => 0,
			'allow_private_endpoint'     => 0,
			'external_service_consent'  => 0,
			'auto_lint'  => 1,
			'accepted'   => 0,
		)
	);
}
register_activation_hook( __FILE__, 'abh_activate' );

/**
 * Desactivación: retira el cron del feed para no dejarlo huérfano.
 */
function abh_deactivate() {
	ABH_CVE::unschedule();
}
register_deactivation_hook( __FILE__, 'abh_deactivate' );

/**
 * Enlace rápido a los ajustes desde la lista de plugins.
 *
 * @param array $links Enlaces existentes.
 * @return array
 */
function abh_action_links( $links ) {
	$url = admin_url( 'admin.php?page=' . ABH_SLUG . '-settings' );
	array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'ai-bug-hunter' ) . '</a>' );
	return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'abh_action_links' );
