<?php
/**
 * Criptografía local para secretos, propuestas pendientes y respaldos.
 *
 * La clave de cifrado no se guarda en la base de datos. Se deriva de las salts
 * de WordPress o, preferentemente, de la constante ABH_SECRET_KEY definida en
 * wp-config.php. Cambiar ambas fuentes invalida datos cifrados anteriores.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Deriva claves y sella lo que no debe poder alterarse entre la vista previa y la aplicación.
 *
 * POR QUE EXISTE:  El plan pendiente es lo que se escribe en disco al pulsar Aplicar. Si no va sellado, quien tenga acceso a la base de datos puede cambiar el parche después de que el dueño lo apruebe.
 *
 * SI LO RECORTAS:  Aquí sí se para si no hay con qué sellar, y es de los pocos sitios donde eso es correcto. Las copias de deshacer, en cambio, NO se cifran: ver la nota en ABH_Transaction::guardar_copia().
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
 * Class ABH_Crypto
 */
class ABH_Crypto {

	const PREFIX = 'ABH1';

	/**
	 * Indica si existe un backend de cifrado autenticado disponible.
	 *
	 * @return bool
	 */
	public static function available() {
		return function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt' )
			|| ( function_exists( 'openssl_encrypt' ) && in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true ) );
	}

	/**
	 * Deriva una clave separada por propósito.
	 *
	 * @param string $purpose Propósito criptográfico.
	 * @return string|false Clave binaria de 32 bytes.
	 */
	private static function key( $purpose ) {
		$material = '';
		if ( defined( 'ABH_SECRET_KEY' ) && is_string( ABH_SECRET_KEY ) && strlen( ABH_SECRET_KEY ) >= 32 ) {
			$material = ABH_SECRET_KEY;
		} elseif ( function_exists( 'wp_salt' ) ) {
			$material = wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' );
		}

		if ( '' === $material ) {
			return false;
		}

		$ikm = hash( 'sha256', $material . '|' . wp_normalize_path( ABSPATH ), true );
		return hash_hkdf( 'sha256', $ikm, 32, 'AI Bug Hunter/' . (string) $purpose, 'ABH-v1' );
	}

	/**
	 * Cifra texto con autenticación.
	 *
	 * @param string $plaintext Texto plano.
	 * @param string $purpose   Propósito/AAD.
	 * @return string|false
	 */
	public static function encrypt( $plaintext, $purpose ) {
		$key = self::key( $purpose );
		if ( false === $key || ! self::available() ) {
			return false;
		}

		try {
			if ( function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt' ) ) {
				$nonce  = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
				$cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( (string) $plaintext, (string) $purpose, $nonce, $key );
				if ( function_exists( 'sodium_memzero' ) ) {
					sodium_memzero( $key );
				}
				return self::PREFIX . ':XCHACHA:' . base64_encode( $nonce . $cipher );
			}

			$iv  = random_bytes( 12 );
			$tag = '';
			$cipher = openssl_encrypt(
				(string) $plaintext,
				'aes-256-gcm',
				$key,
				OPENSSL_RAW_DATA,
				$iv,
				$tag,
				(string) $purpose,
				16
			);
			if ( false === $cipher ) {
				return false;
			}
			return self::PREFIX . ':GCM:' . base64_encode( $iv . $tag . $cipher );
		} catch ( Exception $e ) {
			return false;
		} catch ( Error $e ) {
			return false;
		}
	}

	/**
	 * Descifra y autentica un valor creado por encrypt().
	 *
	 * @param string $payload Carga cifrada.
	 * @param string $purpose Propósito/AAD.
	 * @return string|false
	 */
	public static function decrypt( $payload, $purpose ) {
		$key = self::key( $purpose );
		if ( false === $key || ! is_string( $payload ) ) {
			return false;
		}

		$parts = explode( ':', $payload, 3 );
		if ( 3 !== count( $parts ) || self::PREFIX !== $parts[0] ) {
			return false;
		}

		$raw = base64_decode( $parts[2], true );
		if ( false === $raw ) {
			return false;
		}

		try {
			if ( 'XCHACHA' === $parts[1] && function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_decrypt' ) ) {
				$nlen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
				if ( strlen( $raw ) <= $nlen ) {
					return false;
				}
				$nonce  = substr( $raw, 0, $nlen );
				$cipher = substr( $raw, $nlen );
				$plain  = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $cipher, (string) $purpose, $nonce, $key );
				if ( function_exists( 'sodium_memzero' ) ) {
					sodium_memzero( $key );
				}
				return false === $plain ? false : $plain;
			}

			if ( 'GCM' === $parts[1] && function_exists( 'openssl_decrypt' ) ) {
				if ( strlen( $raw ) <= 28 ) {
					return false;
				}
				$iv     = substr( $raw, 0, 12 );
				$tag    = substr( $raw, 12, 16 );
				$cipher = substr( $raw, 28 );
				$plain  = openssl_decrypt(
					$cipher,
					'aes-256-gcm',
					$key,
					OPENSSL_RAW_DATA,
					$iv,
					$tag,
					(string) $purpose
				);
				return false === $plain ? false : $plain;
			}
		} catch ( Exception $e ) {
			return false;
		} catch ( Error $e ) {
			return false;
		}

		return false;
	}

	/**
	 * Prueba que una carga pertenece a este formato.
	 *
	 * @param mixed $value Valor.
	 * @return bool
	 */
	public static function is_encrypted( $value ) {
		return is_string( $value ) && 0 === strpos( $value, self::PREFIX . ':' );
	}
}
