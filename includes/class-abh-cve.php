<?php
/**
 * Alimentación automática de vulnerabilidades conocidas del núcleo.
 *
 * La tabla de ABH_Core::known_vulnerabilities() se escribe a mano y envejece.
 * Esta clase la amplía desde un feed externo a través del filtro que ya existe,
 * sin tocar el código cada vez que sale un CVE.
 *
 * La regla que gobierna todo este archivo, y que ya estuvo a punto de costarnos
 * recomendar una versión con un RCE sin autenticar activo:
 *
 *   EL DESTINO SEGURO ES SIEMPRE UNA VERSIÓN IGUAL O SUPERIOR A LA AFECTADA,
 *   Y NUNCA UNA QUE CAIGA DENTRO DE OTRO RANGO VULNERABLE.
 *
 * Un feed es contenido observado, no una instrucción: se valida entrada por
 * entrada y se descarta lo que no cumpla. Preferimos perder un aviso antes que
 * proponer una actualización que deje el sitio peor de como estaba.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Descarga un feed externo de vulnerabilidades.
 *
 * POR QUE EXISTE:  Saber que un plugin del sitio tiene un CVE conocido cambia el diagnóstico.
 *
 * SI LO RECORTAS:  El feed es contenido de terceros: se trata como datos. Nada de lo que llegue por ahí dirige una reparación.
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
 * Class ABH_CVE
 */
class ABH_CVE {

	/**
	 * Entradas validadas del feed.
	 */
	const OPTION = 'abh_cve_entries';

	/**
	 * Estado de la última sincronización.
	 */
	const STATUS = 'abh_cve_status';

	/**
	 * Hook del cron diario.
	 */
	const CRON_HOOK = 'abh_cve_refresh';

	/**
	 * Tope de entradas que se aceptan de un feed.
	 */
	const MAX_ENTRIES = 200;

	/**
	 * Engancha el filtro y el cron.
	 *
	 * @return void
	 */
	public static function init() {
		add_filter( 'abh_core_known_vulnerabilities', array( __CLASS__, 'merge' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		if ( '' !== self::feed_url() && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Dirección del feed.
	 *
	 * Vacía por defecto y a propósito: nadie decide por el dueño a qué tercero
	 * consulta su servidor. Se activa con una constante en wp-config.php o con
	 * un filtro, igual que el resto de endpoints del plugin.
	 *
	 * @return string
	 */
	public static function feed_url() {
		$url = defined( 'ABH_CVE_FEED_URL' ) ? (string) ABH_CVE_FEED_URL : '';
		$url = (string) apply_filters( 'abh_cve_feed_url', $url );
		if ( '' === $url ) {
			return '';
		}
		// Solo https y solo direcciones bien formadas: un feed por http sería un
		// canal de inyección directo a la tabla de vulnerabilidades.
		if ( 0 !== strpos( $url, 'https://' ) || ! wp_http_validate_url( $url ) ) {
			return '';
		}
		return $url;
	}

	/**
	 * Descarga el feed, lo valida y guarda solo lo que sobrevive.
	 *
	 * @return array Resumen de la sincronización.
	 */
	public static function refresh() {
		$url = self::feed_url();
		if ( '' === $url ) {
			return self::set_status( false, __( 'There is no feed configured.', 'ai-bug-hunter' ), 0, 0 );
		}

		// Petición cerrada, con el mismo criterio que la del proveedor de modelo:
		// variante segura —el destino se revalida contra rangos internos—, cero
		// redirecciones y tope de descarga en el transporte. El control de tamaño
		// de más abajo solo puede actuar cuando el cuerpo entero ya está en
		// memoria, así que el corte de verdad hay que pedirlo aquí arriba.
		$res = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => 20,
				'sslverify'           => true,
				'redirection'         => 0,
				'reject_unsafe_urls'  => true,
				'limit_response_size' => 2097152,
			)
		);
		if ( is_wp_error( $res ) ) {
			return self::set_status( false, __( 'I could not download the vulnerability feed.', 'ai-bug-hunter' ), 0, 0 );
		}
		$codigo = (int) wp_remote_retrieve_response_code( $res );
		// Ya no se sigue ningún salto, así que una redirección llega aquí como
		// respuesta con cuerpo vacío. Sin este corte pasaría por un feed válido
		// que simplemente no trae vulnerabilidades, que es justo lo contrario de
		// lo que ha ocurrido: no hemos leído el feed.
		if ( $codigo >= 300 && $codigo < 400 ) {
			return self::set_status( false, __( 'The vulnerability feed answered with a redirect, and redirects are not followed. Configure the final HTTPS address of the feed.', 'ai-bug-hunter' ), 0, 0 );
		}
		if ( 200 !== $codigo ) {
			return self::set_status( false, __( 'I could not download the vulnerability feed.', 'ai-bug-hunter' ), 0, 0 );
		}
		$cuerpo = (string) wp_remote_retrieve_body( $res );
		// Segunda comprobación, por si el transporte no honró el tope.
		if ( strlen( $cuerpo ) > 2097152 ) {
			return self::set_status( false, __( 'The feed is disproportionately large; it was discarded for security reasons.', 'ai-bug-hunter' ), 0, 0 );
		}
		$json = json_decode( $cuerpo, true );
		if ( ! is_array( $json ) ) {
			return self::set_status( false, __( 'The feed did not return valid JSON.', 'ai-bug-hunter' ), 0, 0 );
		}
		$crudas = isset( $json['vulnerabilities'] ) && is_array( $json['vulnerabilities'] ) ? $json['vulnerabilities'] : $json;
		if ( ! is_array( $crudas ) ) {
			return self::set_status( false, __( 'The feed does not have the expected shape.', 'ai-bug-hunter' ), 0, 0 );
		}

		$validas     = array();
		$descartadas = 0;
		foreach ( array_slice( $crudas, 0, self::MAX_ENTRIES ) as $cruda ) {
			$limpia = self::sanitize_entry( $cruda );
			if ( false === $limpia ) {
				$descartadas++;
				continue;
			}
			$validas[] = $limpia;
		}

		update_option( self::OPTION, $validas, false );
		return self::set_status(
			true,
			sprintf(
				/* translators: 1: entradas aceptadas, 2: entradas descartadas. */
				__( 'Feed synchronized: %1$d entries accepted, %2$d discarded for not meeting the security rules.', 'ai-bug-hunter' ),
				count( $validas ),
				$descartadas
			),
			count( $validas ),
			$descartadas
		);
	}

	/**
	 * Valida una entrada del feed. Devuelve false si no se puede confiar.
	 *
	 * @param mixed $e Entrada cruda.
	 * @return array|false
	 */
	public static function sanitize_entry( $e ) {
		if ( ! is_array( $e ) ) {
			return false;
		}
		$id = isset( $e['id'] ) ? sanitize_text_field( (string) $e['id'] ) : '';
		// Identificador con forma reconocible. Sin id no hay trazabilidad, y sin
		// trazabilidad no se puede alarmar a nadie de forma responsable.
		if ( ! preg_match( '/^(CVE-\d{4}-\d{4,7}|GHSA-[A-Za-z0-9-]{4,40}|WPVDB-[A-Za-z0-9-]{4,40})$/', $id ) ) {
			return false;
		}
		$rangos_crudos = isset( $e['rangos'] ) && is_array( $e['rangos'] )
			? $e['rangos']
			: ( isset( $e['ranges'] ) && is_array( $e['ranges'] ) ? $e['ranges'] : array() );
		if ( empty( $rangos_crudos ) ) {
			return false;
		}

		$rangos = array();
		foreach ( array_slice( $rangos_crudos, 0, 20 ) as $r ) {
			if ( ! is_array( $r ) ) {
				continue;
			}
			$desde  = self::clean_version( isset( $r['desde'] ) ? $r['desde'] : ( isset( $r['from'] ) ? $r['from'] : '' ) );
			$hasta  = self::clean_version( isset( $r['hasta'] ) ? $r['hasta'] : ( isset( $r['to'] ) ? $r['to'] : '' ) );
			$parche = self::clean_version( isset( $r['parche'] ) ? $r['parche'] : ( isset( $r['patched'] ) ? $r['patched'] : '' ) );
			if ( '' === $desde || '' === $hasta || '' === $parche ) {
				continue;
			}
			// El rango debe tener sentido: [desde, hasta) con hasta por encima.
			if ( version_compare( $desde, $hasta, '>=' ) ) {
				continue;
			}
			// LA REGLA: el parche no puede estar por debajo del inicio del rango
			// afectado. Un feed que proponga bajar de versión se descarta, porque
			// así es exactamente como se acaba recomendando volver a un RCE.
			if ( version_compare( $parche, $desde, '<' ) ) {
				continue;
			}
			// Y el parche tampoco puede caer DENTRO del propio rango vulnerable.
			if ( version_compare( $parche, $desde, '>=' ) && version_compare( $parche, $hasta, '<' ) ) {
				continue;
			}
			$rangos[] = array( 'desde' => $desde, 'hasta' => $hasta, 'parche' => $parche );
		}
		if ( empty( $rangos ) ) {
			return false;
		}

		$sev = strtolower( sanitize_text_field( (string) ( isset( $e['severidad'] ) ? $e['severidad'] : ( isset( $e['severity'] ) ? $e['severity'] : 'alta' ) ) ) );
		if ( ! in_array( $sev, array( 'critica', 'alta', 'media', 'baja' ), true ) ) {
			$sev = 'alta';
		}
		$resumen = isset( $e['resumen'] ) ? $e['resumen'] : ( isset( $e['summary'] ) ? $e['summary'] : '' );
		$resumen = wp_strip_all_tags( (string) $resumen );
		$resumen = function_exists( 'mb_substr' ) ? mb_substr( $resumen, 0, 600 ) : substr( $resumen, 0, 600 );

		return array(
			'id'        => $id,
			'alias'     => sanitize_text_field( (string) ( isset( $e['alias'] ) ? $e['alias'] : '' ) ),
			'severidad' => $sev,
			// Se guarda el texto del feed tal cual, sin adornos. La atribución al
			// origen se compone al leer, en entries(), para no acumular prefijos
			// cada vez que una entrada guardada vuelve a pasar por aquí.
			'resumen'   => '' !== $resumen ? $resumen : __( 'The feed did not include a description for this entry.', 'ai-bug-hunter' ),
			'rangos'    => $rangos,
			'fuente'    => 'feed',
		);
	}

	/**
	 * Normaliza una cadena de versión, o devuelve vacío si no lo es.
	 *
	 * @param mixed $v Valor.
	 * @return string
	 */
	private static function clean_version( $v ) {
		$v = trim( (string) $v );
		return preg_match( '/^[0-9]+(\.[0-9]+){0,3}$/', $v ) ? $v : '';
	}

	/**
	 * Servidor del feed, para poder citar el origen de cada aviso.
	 *
	 * @return string
	 */
	private static function feed_host() {
		$host = (string) wp_parse_url( self::feed_url(), PHP_URL_HOST );
		return '' !== $host ? $host : __( 'not recorded', 'ai-bug-hunter' );
	}

	/**
	 * Entradas guardadas, revalidadas al leerlas.
	 *
	 * Se revalidan a propósito: la opción vive en la base de datos y podría
	 * haberse alterado por fuera desde que se escribió. Aquí es también donde
	 * cada aviso recibe su atribución de origen.
	 *
	 * @return array
	 */
	public static function entries() {
		$guardadas = get_option( self::OPTION, array() );
		if ( ! is_array( $guardadas ) ) {
			return array();
		}
		$out = array();
		// Todo lo que sale de aquí termina en una pantalla, así que sale citando
		// quién lo publica y marcado como informativo. El feed es de un tercero:
		// el plugin repite lo que dice, no lo suscribe, y no está en posición de
		// afirmar por su cuenta que una versión concreta esté siendo atacada.
		// Con el origen delante, quien lo lea puede ir a comprobarlo.
		$origen = self::feed_host();
		foreach ( array_slice( $guardadas, 0, self::MAX_ENTRIES ) as $e ) {
			$limpia = self::sanitize_entry( $e );
			if ( false !== $limpia ) {
				$limpia['resumen'] = sprintf(
					/* translators: 1: servidor del feed configurado, 2: texto del aviso publicado por el feed. */
					__( 'Informational advisory from the vulnerability feed configured for this site (source: %1$s): %2$s', 'ai-bug-hunter' ),
					$origen,
					$limpia['resumen']
				);
				$out[] = $limpia;
			}
		}
		return $out;
	}

	/**
	 * Añade las entradas del feed a la tabla del núcleo.
	 *
	 * La tabla escrita a mano manda: si un id ya está en ella, el feed no lo
	 * pisa. Lo verificado a mano no se degrada con lo automático.
	 *
	 * @param array $tabla Tabla de ABH_Core.
	 * @return array
	 */
	public static function merge( $tabla ) {
		if ( ! is_array( $tabla ) ) {
			$tabla = array();
		}
		$ids = array();
		foreach ( $tabla as $v ) {
			if ( isset( $v['id'] ) ) {
				$ids[ strtoupper( (string) $v['id'] ) ] = true;
			}
		}
		foreach ( self::entries() as $e ) {
			if ( isset( $ids[ strtoupper( $e['id'] ) ] ) ) {
				continue;
			}
			$tabla[] = $e;
			$ids[ strtoupper( $e['id'] ) ] = true;
		}
		return $tabla;
	}

	/**
	 * Guarda y devuelve el estado de la última sincronización.
	 *
	 * @param bool   $ok          Si salió bien.
	 * @param string $mensaje     Mensaje legible.
	 * @param int    $aceptadas   Entradas aceptadas.
	 * @param int    $descartadas Entradas descartadas.
	 * @return array
	 */
	private static function set_status( $ok, $mensaje, $aceptadas, $descartadas ) {
		$estado = array(
			'ok'       => (bool) $ok,
			'message'  => $mensaje,
			'accepted' => (int) $aceptadas,
			'rejected' => (int) $descartadas,
			'at'       => time(),
		);
		update_option( self::STATUS, $estado, false );
		return $estado;
	}

	/**
	 * Estado de la última sincronización.
	 *
	 * @return array
	 */
	public static function status() {
		$e = get_option( self::STATUS, array() );
		if ( ! is_array( $e ) || ! isset( $e['at'] ) ) {
			return array( 'ok' => false, 'message' => '', 'accepted' => 0, 'rejected' => 0, 'at' => 0 );
		}
		return $e;
	}

	/**
	 * Retira el cron. Se llama al desactivar el plugin.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}
}
