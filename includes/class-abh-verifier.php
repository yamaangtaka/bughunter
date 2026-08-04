<?php
/**
 * Verificación: nada se escribe sin comprobar la sintaxis, nada queda escrito
 * sin comprobar que el sitio sigue de pie.
 *
 * La comprobación de sintaxis se hace con el analizador léxico propio de PHP
 * (token_get_all con TOKEN_PARSE), que detecta errores de sintaxis SIN ejecutar
 * el código y sin necesitar acceso a la consola del servidor.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Comprueba que el código propuesto compila.
 *
 * POR QUE EXISTE:  Es una señal, y una buena.
 *
 * SI LO RECORTAS:  Es AVISO, no veto. Un fragmento legítimo puede no compilar suelto, y el PHP de este panel no siempre es el que ejecuta el archivo. Convertirlo en bloqueo mata reparaciones correctas.
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
 * Class ABH_Verifier
 */
class ABH_Verifier {

	/**
	 * Marcadores de que el sitio está roto.
	 *
	 * @return array
	 */
	public static function critical_markers() {
		return array(
			'There has been a critical error on this website',
			'Ha ocurrido un error crítico en esta web',
			'Error grave en esta web',
			'Parse error:',
			'Fatal error:',
		);
	}

	/**
	 * Checks the syntax of a PHP fragment without executing it.
	 *
	 * @param string $code Código.
	 * @return array ok, detail, method
	 */
	public static function lint( $code ) {
		if ( function_exists( 'token_get_all' ) && defined( 'TOKEN_PARSE' ) ) {
			try {
				token_get_all( $code, TOKEN_PARSE );
				return array(
					'ok'     => true,
					'detail' => __( 'Valid PHP syntax.', 'ai-bug-hunter' ),
					'method' => 'token_get_all',
				);
			} catch ( ParseError $e ) {
				return array(
					'ok'     => false,
					'detail' => $e->getMessage() . ' (line ' . $e->getLine() . ')',
					'method' => 'token_get_all',
				);
			} catch ( Error $e ) {
				return array(
					'ok'     => false,
					'detail' => $e->getMessage(),
					'method' => 'token_get_all',
				);
			}
		}
		return self::heuristic( $code );
	}

	/**
	 * Comprobación estructural mínima si el analizador no está disponible.
	 *
	 * @param string $code Código.
	 * @return array
	 */
	public static function heuristic( $code ) {
		$stripped = preg_replace( '#/\*.*?\*/#s', '', $code );
		$stripped = preg_replace( '#//[^\n]*#', '', (string) $stripped );
		$stripped = preg_replace( '#\'(?:\\\\.|[^\'\\\\])*\'#s', "''", (string) $stripped );
		$stripped = preg_replace( '#"(?:\\\\.|[^"\\\\])*"#s', '""', (string) $stripped );

		$pairs = array(
			'{' => '}',
			'(' => ')',
			'[' => ']',
		);
		$stack = array();
		$len   = strlen( (string) $stripped );
		for ( $i = 0; $i < $len; $i++ ) {
			$ch = $stripped[ $i ];
			if ( isset( $pairs[ $ch ] ) ) {
				$stack[] = $ch;
			} elseif ( in_array( $ch, $pairs, true ) ) {
				$open = array_pop( $stack );
				if ( null === $open || $pairs[ $open ] !== $ch ) {
					return array(
						'ok'     => false,
						/* translators: %s: carácter delimitador. */
						'detail' => sprintf( __( 'Delimiter «%s» with no matching opening.', 'ai-bug-hunter' ), $ch ),
						'method' => 'heuristic',
					);
				}
			}
		}
		if ( ! empty( $stack ) ) {
			return array(
				'ok'     => false,
				/* translators: %s: delimitadores sin cerrar. */
				'detail' => sprintf( __( 'Left unclosed: %s', 'ai-bug-hunter' ), implode( '', $stack ) ),
				'method' => 'heuristic',
			);
		}
		return array(
			'ok'     => true,
			'detail' => __( 'Delimiters balanced.', 'ai-bug-hunter' ),
			'method' => 'heuristic',
		);
	}

	/**
	 * Determina si el estado posterior es objetivamente peor que la línea base.
	 * No exige que un sitio ya roto quede sano con un único microparche, pero sí
	 * revierte cuando pierde conectividad o aparece un error de servidor nuevo.
	 *
	 * @param array $baseline Estado anterior.
	 * @param array $after    Estado posterior.
	 * @return bool
	 */
	public static function worsened( $baseline, $after ) {
		// PUERTA A PUERTA cuando las dos lecturas la traen. El resumen `status`
		// puede venir de la portada en una lectura y del escritorio en la otra,
		// y compararlos entre sí saca conclusiones falsas en las dos
		// direcciones: en un sitio cuyo escritorio ya fallaba, un parche que
		// tiraba la portada se leía como «ya estaba mal antes» y NO se revertía.
		// Basta con que UNA puerta que estaba sana deje de estarlo.
		if ( ! empty( $baseline['puertas'] ) && ! empty( $after['puertas'] ) && is_array( $baseline['puertas'] ) && is_array( $after['puertas'] ) ) {
			foreach ( $baseline['puertas'] as $nombre => $antes ) {
				if ( ! isset( $after['puertas'][ $nombre ] ) ) {
					continue;
				}
				$ahora = $after['puertas'][ $nombre ];
				// No concluyente en ESA puerta: no es prueba de daño. Se salta
				// sólo esa; si la otra empeoró de verdad, se revierte igual.
				if ( ! empty( $ahora['inconclusive'] ) ) {
					continue;
				}
				// Y si la puerta no se pudo medir ANTES, tampoco hay con qué
				// comparar: `puerta_peor()` exige `before_ok` o `before_status`
				// y los dos vienen vacíos de una lectura no concluyente, así que
				// devolvía false en silencio. Eso convertía un 500 recién
				// aparecido en «ya estaba mal antes». No se revierte —no hay
				// prueba de que este cambio lo causara— pero tampoco se afirma
				// lo contrario: la marca sube para que el mensaje diga la verdad.
				if ( ! empty( $antes['inconclusive'] ) ) {
					continue;
				}
				if ( self::puerta_peor( $antes, $ahora ) ) {
					return true;
				}
			}
			return false;
		}

		return self::puerta_peor( $baseline, $after, ! empty( $after['inconclusive'] ) );
	}

	/**
	 * ¿El fallo de ahora es uno que NO se pudo medir antes?
	 *
	 * Distingue «ya estaba mal» de «no llegamos a mirarlo». Sin esta distinción
	 * el mensaje afirmaba que el sitio ya presentaba el problema, cuando lo
	 * único cierto es que la línea base de esa puerta no se pudo tomar — y el
	 * dueño salía a buscar un problema anterior que quizá nunca existió.
	 *
	 * @param array $baseline Lectura anterior.
	 * @param array $after    Lectura posterior.
	 * @return bool
	 */
	public static function sin_comparacion( $baseline, $after ) {
		if ( empty( $baseline['puertas'] ) || empty( $after['puertas'] ) || ! is_array( $baseline['puertas'] ) || ! is_array( $after['puertas'] ) ) {
			return false;
		}
		foreach ( $after['puertas'] as $nombre => $ahora ) {
			if ( ! empty( $ahora['ok'] ) || ! empty( $ahora['inconclusive'] ) ) {
				continue;
			}
			// Esta puerta está mal AHORA y de forma concluyente. ¿Se pudo medir
			// antes? Si no, no hay nada que comparar.
			if ( isset( $baseline['puertas'][ $nombre ] ) && ! empty( $baseline['puertas'][ $nombre ]['inconclusive'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * ¿Esta puerta concreta está peor que antes?
	 *
	 * @param array $antes        Lectura anterior.
	 * @param array $ahora        Lectura posterior.
	 * @param bool  $inconcluyente Si la lectura posterior no llegó a hacerse.
	 * @return bool
	 */
	private static function puerta_peor( $antes, $ahora, $inconcluyente = false ) {
		// Una comprobación NO CONCLUYENTE (bloqueada por firewall/hosting) no es
		// prueba de que el sitio empeoró. Revertir por ella destruiría un arreglo
		// bueno; se conserva el cambio y se avisa con claridad al usuario.
		if ( $inconcluyente ) {
			return false;
		}

		$before_ok     = ! empty( $antes['ok'] );
		$after_ok      = ! empty( $ahora['ok'] );
		$before_status = isset( $antes['status'] ) ? (int) $antes['status'] : 0;
		$after_status  = isset( $ahora['status'] ) ? (int) $ahora['status'] : 0;

		if ( $before_ok && ! $after_ok ) {
			return true;
		}
		if ( $before_status > 0 && 0 === $after_status ) {
			return true;
		}
		if ( $before_status > 0 && $before_status < 500 && $after_status >= 500 ) {
			return true;
		}
		return false;
	}

	/**
	 * Comprueba que el sitio responde y no muestra un error crítico.
	 *
	 * Sondea DOS puertas, no una. La portada sola dejaba pasar sin una queja un
	 * `permisos 0600` sobre un archivo del escritorio, un `quitar` de un
	 * mu-plugin del backend o una escritura en `wp-admin`: nada de eso se ve
	 * desde la home, así que la reversión automática nunca llegaba a dispararse
	 * justo para el tipo de operación que más lo necesita.
	 *
	 * La segunda sonda es `wp-login.php` porque es la única puerta pública que
	 * arranca WordPress entero con todos los plugins cargados. Va con menos
	 * plazo a propósito: dos esperas de 20 s se comen el `max_execution_time`
	 * de 30 s que trae casi todo el hosting compartido, y morir por tiempo aquí
	 * dejaría el cambio aplicado y sin veredicto.
	 *
	 * Un fallo de RED en la segunda no cuenta como daño: se devuelve la lectura
	 * de la portada. Sólo un 500 o un marcador crítico mandan.
	 *
	 * @return array ok, status, detail, inconclusive
	 */
	public static function health_check() {
		// Los plazos suman 20 s, los mismos que costaba la única sonda de antes.
		// Cada aplicación llama aquí DOS veces —línea base y comprobación
		// posterior—, así que subirlos se come el max_execution_time de 30 s que
		// trae casi todo el hosting compartido, y morir por tiempo dejaría el
		// cambio escrito y sin veredicto.
		$portada = self::sondear( home_url( '/' ), 12 );
		// 8 s, no 5: con 5 el `wp-login.php` de un hosting compartido pasa de
		// plazo con normalidad, y una puerta que sale «no concluyente» en la
		// LÍNEA BASE es peor que no medirla — deja el después sin nada con qué
		// compararse. Sigue sumando 20 s, lo mismo que costaba la única sonda
		// anterior, y cada aplicación llama aquí dos veces.
		$login = self::sondear( wp_login_url(), 8 );

		// CADA PUERTA SE GUARDA POR SEPARADO. Devolver un único `status` mezclado
		// hacía que worsened() comparara la portada de antes contra el escritorio
		// de después —o al revés— y sacara conclusiones falsas: en un sitio cuyo
		// wp-login.php ya fallaba, un parche que tiraba la PORTADA se leía como
		// «ya estaba mal antes» y no se revertía nada.
		$puertas = array(
			'portada'    => array( 'ok' => ! empty( $portada['ok'] ), 'status' => isset( $portada['status'] ) ? (int) $portada['status'] : 0, 'inconclusive' => ! empty( $portada['inconclusive'] ) ),
			'escritorio' => array( 'ok' => ! empty( $login['ok'] ), 'status' => isset( $login['status'] ) ? (int) $login['status'] : 0, 'inconclusive' => ! empty( $login['inconclusive'] ) ),
		);

		if ( empty( $portada['ok'] ) ) {
			$portada['puertas'] = $puertas;
			return $portada;
		}

		if ( empty( $login['ok'] ) && empty( $login['inconclusive'] ) ) {
			return array(
				'ok'      => false,
				'status'  => isset( $login['status'] ) ? $login['status'] : 0,
				'puertas' => $puertas,
				// Marca la puerta de la que viene el veredicto, para que el
				// mensaje de arriba no cuente lo de la portada como si fuera
				// esto: son dos sitios distintos del sitio.
				'puerta'  => 'escritorio',
				/* translators: %s: detalle del fallo en el escritorio. */
				'detail'  => sprintf( __( 'The front page responds fine, but the entry to the dashboard does not: %s', 'ai-bug-hunter' ), $login['detail'] ),
			);
		}

		$portada['puertas'] = $puertas;
		return $portada;
	}

	/**
	 * Una sola petición de comprobación contra una URL del propio sitio.
	 *
	 * @param string $url     URL a sondear.
	 * @param int    $timeout Segundos de plazo.
	 * @return array ok, status, detail, inconclusive
	 */
	private static function sondear( $url, $timeout = 20 ) {
		$res = wp_remote_get(
			add_query_arg( 'abh_hc', time(), $url ),
			array(
				'timeout'     => max( 1, (int) $timeout ),
				'redirection' => 3,
				'sslverify'   => true,
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);

		if ( is_wp_error( $res ) ) {
			return array(
				'ok'     => false,
				'status' => 0,
				// NO CONCLUYENTE, y la diferencia lo es todo. Que la petición no
				// llegue —un timeout de cURL, un DNS lento, un cortafuegos que
				// no deja al servidor hablar consigo mismo— no es prueba de que
				// el sitio esté peor. Sin esta marca, un hipo de red de veinte
				// segundos hacía que se revirtiera una reparación BUENA y se le
				// dijera al dueño que su cambio había roto el sitio.
				'inconclusive' => true,
				/* translators: %s: mensaje de error. */
				'detail' => sprintf( __( 'The site could not be checked: %s', 'ai-bug-hunter' ), $res->get_error_message() ),
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $res );
		$body   = (string) wp_remote_retrieve_body( $res );

		foreach ( self::critical_markers() as $marker ) {
			if ( false !== stripos( $body, $marker ) ) {
				return array(
					'ok'     => false,
					'status' => $status,
					/* translators: 1: código HTTP, 2: texto encontrado. */
					'detail' => sprintf( __( 'The site responds %1$d but shows: «%2$s»', 'ai-bug-hunter' ), $status, $marker ),
				);
			}
		}

		if ( $status >= 500 ) {
			return array(
				'ok'     => false,
				'status' => $status,
				/* translators: %d: código HTTP. */
				'detail' => sprintf( __( 'The site responds with HTTP error %d.', 'ai-bug-hunter' ), $status ),
			);
		}

		// Códigos que NO prueban que el sitio esté sano: alguien (firewall,
		// protección del hosting, autenticación o un límite de peticiones)
		// bloqueó la comprobación antes de que llegara a PHP. Declararlo
		// "verificado" sería mentir: es NO CONCLUYENTE, no exitoso.
		if ( in_array( $status, array( 401, 403, 407, 429 ), true ) ) {
			return array(
				'ok'           => false,
				'inconclusive' => true,
				'status'       => $status,
				/* translators: %d: código HTTP. */
				'detail'       => sprintf( __( 'The site could not be checked: the request was blocked with HTTP %d (firewall, hosting protection or authentication). This neither confirms nor rules out that the fix works.', 'ai-bug-hunter' ), $status ),
			);
		}

		return array(
			'ok'     => true,
			'status' => $status,
			/* translators: %d: código HTTP. */
			'detail' => sprintf( __( 'The site responds HTTP %d and with no visible errors.', 'ai-bug-hunter' ), $status ),
		);
	}
}
