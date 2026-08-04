<?php
/**
 * Estado verificable de la conexión con el proveedor de IA.
 *
 * Conserva únicamente una huella local de la configuración que respondió,
 * nunca la clave, el endpoint completo ni el contenido enviado.
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ABH_AI_Connection
 */
class ABH_AI_Connection {

	const TRANSIENT_PREFIX = 'abh_ai_ok_';
	const TTL              = 604800;

	/**
	 * Registra que la configuración exacta recibió una respuesta válida.
	 *
	 * @param array<string,mixed> $settings Ajustes usados en la llamada.
	 * @return void
	 */
	public static function record_success( $settings ) {
		$fingerprint = self::fingerprint( $settings );
		if ( '' === $fingerprint ) {
			return;
		}

		set_transient(
			self::TRANSIENT_PREFIX . substr( $fingerprint, 0, 40 ),
			array(
				'checked_at' => time(),
				'provider'   => isset( $settings['provider'] ) ? sanitize_key( $settings['provider'] ) : '',
				'model'      => self::effective_model( $settings ),
			),
			self::TTL
		);
	}

	/**
	 * Describe la configuración actual sin exponer secretos.
	 *
	 * @param array<string,mixed>|null $settings Ajustes; null usa los guardados.
	 * @return array<string,mixed>
	 */
	public static function status( $settings = null ) {
		$settings    = is_array( $settings ) ? $settings : ABH_Router::settings();
		$provider    = isset( $settings['provider'] ) ? sanitize_key( $settings['provider'] ) : '';
		$configured  = ABH_Router::is_configured( $settings );
		$fingerprint = self::fingerprint( $settings );
		$record      = '' !== $fingerprint
			? get_transient( self::TRANSIENT_PREFIX . substr( $fingerprint, 0, 40 ) )
			: false;
		$verified    = $configured && is_array( $record ) && ! empty( $record['checked_at'] );

		return array(
			'state'       => $verified ? 'verified' : ( $configured ? 'configured' : 'unavailable' ),
			'configured'  => $configured,
			'verified'    => $verified,
			'checked_at'  => $verified ? (int) $record['checked_at'] : 0,
			'provider'    => $provider,
			'provider_label' => self::provider_label( $provider, $settings ),
			// Lo que sale hacia la interfaz va enmascarado si tiene forma de
			// credencial. effective_model() se mantiene en claro porque la
			// huella de verificación depende de su valor exacto.
			'model'       => self::display_model( $settings ),
			'model_is_secret' => ABH_Privacy::looks_like_secret( self::effective_model( $settings ) ),
		);
	}

	/**
	 * Modelo tal y como puede mostrarse o enviarse al navegador.
	 *
	 * @param array<string,mixed> $settings Ajustes.
	 * @return string
	 */
	public static function display_model( $settings ) {
		return ABH_Privacy::mask_if_secret( self::effective_model( $settings ) );
	}

	/**
	 * Modelo que debe mostrarse en la interfaz.
	 *
	 * @param array<string,mixed> $settings Ajustes.
	 * @return string
	 */
	public static function effective_model( $settings ) {
		// El modelo es el que hay guardado, y nada más. El nombre por defecto
		// que se rellenaba para el servicio comercial no tiene sentido en esta
		// edición: ese proveedor no puede guardarse ni usarse, así que un ajuste
		// heredado se queda sin modelo y la pantalla dice «no disponible», que
		// es la verdad.
		return isset( $settings['model'] ) ? sanitize_text_field( $settings['model'] ) : '';
	}

	/**
	 * Nombre humano del proveedor, con reconocimiento del endpoint oficial.
	 *
	 * @param string              $provider Proveedor guardado.
	 * @param array<string,mixed> $settings Ajustes.
	 * @return string
	 */
	private static function provider_label( $provider, $settings ) {
		$providers = ABH_Router::providers();
		$label     = isset( $providers[ $provider ]['label'] ) ? (string) $providers[ $provider ]['label'] : '';

		if ( 'compatible' === $provider && ! empty( $settings['base_url'] ) ) {
			$host = wp_parse_url( (string) $settings['base_url'], PHP_URL_HOST );
			if ( is_string( $host ) && 'api.mistral.ai' === strtolower( $host ) ) {
				return __( 'Mistral API', 'ai-bug-hunter' );
			}
		}
		return $label;
	}

	/**
	 * Huella ligada al proveedor, modelo y credencial actuales.
	 *
	 * La clave participa únicamente en un HMAC local; nunca se persiste.
	 *
	 * @param array<string,mixed> $settings Ajustes.
	 * @return string
	 */
	private static function fingerprint( $settings ) {
		if ( ! is_array( $settings ) ) {
			return '';
		}
		$binding = ABH_Router::credential_binding( $settings );
		$model   = self::effective_model( $settings );
		if ( '' === $binding || '' === $model ) {
			return '';
		}
		// La huella se ata a la credencial que introdujo el administrador y a
		// ninguna otra. Aquí había una rama para el servicio comercial: aquel
		// proveedor no guardaba clave en los ajustes y la tomaba del router.
		// Se fue con él, y con ella la llamada a un método que este paquete ya
		// no define.
		$key_marker = isset( $settings['api_key'] ) ? (string) $settings['api_key'] : '';
		return hash_hmac( 'sha256', $binding . "\0" . $model . "\0" . $key_marker, wp_salt( 'auth' ) );
	}
}
