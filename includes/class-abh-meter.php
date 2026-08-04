<?php
/**
 * Medidor único de consumo y política de cobro.
 *
 * Antes había tres contabilidades distintas del mismo gasto: la que la consola
 * iba sumando en el navegador, la que salía en el reporte y la que se guardaba
 * en el historial. Cuando una respuesta traía el consumo de un paso en vez del
 * acumulado, la consola lo tomaba como total y el número bajaba solo. De ahí
 * venía el "acumulado incorrecto".
 *
 * Aquí hay un único libro mayor, en el servidor, con una entrada por
 * incidencia. Todo lo que se muestra sale de él:
 *
 *   consola = reporte = historial = lo que se factura
 *
 * El navegador no suma nada: solo pinta lo que el servidor le da.
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ABH_Meter
 */
class ABH_Meter {

	/**
	 * Libro mayor: incidencia => consumo y liquidación.
	 */
	const OPTION = 'abh_meter_ledger';

	/**
	 * Incidencias conservadas en el libro mayor.
	 */
	const MAX_ENTRIES = 200;

	/**
	 * This edition does not provide an included-token allowance. Any provider
	 * charge is governed by the administrator's own provider account.
	 */
	const FREE_TOKENS = 0;

	/**
	 * Coste de referencia de un ciclo completo con modelo, para poder decir
	 * cuánto ahorró una reparación determinista cuando aún no hay historial.
	 */
	const BASELINE_IN  = 22000;
	const BASELINE_OUT = 4000;

	/**
	 * Libro mayor ya saneado en esta petición.
	 *
	 * El Historial pinta hasta 200 filas y cada una consulta su medidor: sin
	 * esta memoria se reconstruiría el libro entero 200 veces.
	 *
	 * @var array|null
	 */
	private static $memo = null;

	/**
	 * Incidencia a la que se atribuye el consumo de esta petición.
	 *
	 * @var array
	 */
	private static $context = array(
		'key'      => '',
		'job_id'   => '',
		'rel_path' => '',
		'short'    => '',
		'stage'    => '',
	);

	/**
	 * Política de cobro por desenlace.
	 *
	 * Cobrar completo solo cuando la reparación se aplicó. Si el usuario la
	 * rechaza, un mínimo: revisó y decidió, algo recibió. Si hubo que revertir
	 * o el proceso no llegó a conclusión, cero: ese gasto lo asumimos nosotros.
	 *
	 * @return array
	 */
	public static function policy() {
		$defecto = array(
			'free_tokens' => self::FREE_TOKENS,
			'rates'       => array(
				'repaired'      => 1.00,
				'declined'      => 0.10,
				'rolled_back'   => 0.00,
				'deterministic' => 0.00,
				'failed'        => 0.00,
				'inconclusive'  => 0.00,
				'open'          => 0.00,
			),
		);
		$politica = apply_filters( 'abh_meter_policy', $defecto );

		if ( ! is_array( $politica ) || empty( $politica['rates'] ) || ! is_array( $politica['rates'] ) ) {
			return $defecto;
		}
		$politica['free_tokens'] = isset( $politica['free_tokens'] ) ? max( 0, (int) $politica['free_tokens'] ) : self::FREE_TOKENS;
		$politica['rates']       = array_merge( $defecto['rates'], $politica['rates'] );
		foreach ( $politica['rates'] as $k => $v ) {
			$politica['rates'][ $k ] = min( 1.0, max( 0.0, (float) $v ) );
		}
		return $politica;
	}

	/**
	 * Desenlaces que cierran una incidencia.
	 *
	 * @return array
	 */
	public static function outcomes() {
		return array( 'repaired', 'declined', 'rolled_back', 'deterministic', 'failed', 'inconclusive' );
	}

	/**
	 * Atribuye el consumo de esta petición a una incidencia.
	 *
	 * @param string $key      Clave de la incidencia.
	 * @param array  $contexto job_id, rel_path, short.
	 * @return void
	 */
	public static function bind( $key, $contexto = array() ) {
		$key = sanitize_text_field( (string) $key );
		if ( '' === $key ) {
			return;
		}
		self::$context = array(
			'key'      => $key,
			'job_id'   => isset( $contexto['job_id'] ) ? sanitize_text_field( (string) $contexto['job_id'] ) : '',
			'rel_path' => isset( $contexto['rel_path'] ) ? (string) $contexto['rel_path'] : '',
			'short'    => isset( $contexto['short'] ) ? (string) $contexto['short'] : '',
			'stage'    => '',
		);
	}

	/**
	 * Deja de atribuir consumo a ninguna incidencia.
	 *
	 * @return void
	 */
	public static function unbind() {
		self::$context = array( 'key' => '', 'job_id' => '', 'rel_path' => '', 'short' => '', 'stage' => '' );
	}

	/**
	 * Incidencia atribuida ahora mismo.
	 *
	 * @return string
	 */
	public static function bound() {
		return self::$context['key'];
	}

	/**
	 * Atadura completa tal como está ahora.
	 *
	 * Existe para poder apartarse un momento y volver: una consulta de solo
	 * lectura no debe cobrarse a la reparación que esté en curso, pero tampoco
	 * puede dejar el medidor desatado al terminar. bound() devuelve solo la
	 * clave, y con la clave no se reconstruyen ni el paso ni la ruta.
	 *
	 * @return array
	 */
	public static function current() {
		return self::$context;
	}

	/**
	 * Vuelve a una atadura tomada antes con current().
	 *
	 * @param array $contexto Atadura previa.
	 * @return void
	 */
	public static function adopt( $contexto ) {
		if ( ! is_array( $contexto ) || ! isset( $contexto['key'] ) ) {
			return;
		}
		self::$context = array(
			'key'      => sanitize_text_field( (string) $contexto['key'] ),
			'job_id'   => isset( $contexto['job_id'] ) ? sanitize_text_field( (string) $contexto['job_id'] ) : '',
			'rel_path' => isset( $contexto['rel_path'] ) ? (string) $contexto['rel_path'] : '',
			'short'    => isset( $contexto['short'] ) ? (string) $contexto['short'] : '',
			'stage'    => isset( $contexto['stage'] ) ? sanitize_key( (string) $contexto['stage'] ) : '',
		);
	}

	/**
	 * Nombra el paso al que pertenecen las siguientes llamadas al modelo.
	 *
	 * @param string $stage Etiqueta del paso.
	 * @return void
	 */
	public static function stage( $stage ) {
		self::$context['stage'] = sanitize_key( (string) $stage );
	}

	/**
	 * Anota el consumo de una llamada al modelo.
	 *
	 * Lo llama ABH_Router::complete(), que es el único sitio por donde salen
	 * peticiones al proveedor. Nada puede gastar sin pasar por aquí.
	 *
	 * @param array  $usage in, out.
	 * @param string $stage Paso opcional.
	 * @return void
	 */
	public static function record( $usage, $stage = '' ) {
		$key = self::$context['key'];
		if ( '' === $key || ! is_array( $usage ) ) {
			return;
		}
		$in  = isset( $usage['in'] ) ? max( 0, (int) $usage['in'] ) : 0;
		$out = isset( $usage['out'] ) ? max( 0, (int) $usage['out'] ) : 0;
		if ( 0 === $in && 0 === $out ) {
			return;
		}

		$libro = self::ledger();
		$e     = isset( $libro[ $key ] ) ? $libro[ $key ] : self::blank( $key );

		// Una incidencia ya liquidada no se reabre sumando gasto por encima:
		// se reabre de forma explícita, para que el cobro no cambie solo.
		if ( '' !== $e['outcome'] ) {
			$e['outcome']    = '';
			$e['settled_at'] = 0;
			$e['billable']   = array( 'in' => 0, 'out' => 0 );
			$e['reopened']   = (int) $e['reopened'] + 1;
		}

		$paso = '' !== $stage ? sanitize_key( $stage ) : ( '' !== self::$context['stage'] ? self::$context['stage'] : 'sin_etiqueta' );
		if ( ! isset( $e['stages'][ $paso ] ) ) {
			$e['stages'][ $paso ] = array( 'in' => 0, 'out' => 0, 'calls' => 0 );
		}
		$e['stages'][ $paso ]['in']    += $in;
		$e['stages'][ $paso ]['out']   += $out;
		$e['stages'][ $paso ]['calls'] += 1;

		$e['consumed']['in']  += $in;
		$e['consumed']['out'] += $out;
		$e['calls']           += 1;
		$e['last_at']          = time();

		if ( '' === $e['rel_path'] && '' !== self::$context['rel_path'] ) {
			$e['rel_path'] = self::$context['rel_path'];
		}
		if ( '' === $e['short'] && '' !== self::$context['short'] ) {
			$e['short'] = self::$context['short'];
		}
		if ( '' !== self::$context['job_id'] && ! in_array( self::$context['job_id'], $e['jobs'], true ) ) {
			$e['jobs'][] = self::$context['job_id'];
		}

		$libro[ $key ] = $e;
		self::save( $libro );
	}

	/**
	 * Anota una reparación resuelta sin gastar tokens.
	 *
	 * El ahorro no se inventa: se estima con la media de lo que han costado en
	 * esta instalación las incidencias que sí pasaron por el modelo. Mientras
	 * no haya suficientes, se usa una referencia conservadora.
	 *
	 * @param string $key    Clave de la incidencia.
	 * @param string $motivo Qué lo resolvió.
	 * @return array Ahorro estimado.
	 */
	public static function record_avoided( $key, $motivo = '' ) {
		$key = sanitize_text_field( (string) $key );
		if ( '' === $key ) {
			return array( 'in' => 0, 'out' => 0 );
		}
		$libro = self::ledger();
		$e     = isset( $libro[ $key ] ) ? $libro[ $key ] : self::blank( $key );
		$base  = self::baseline();

		$e['avoided']['in']  += (int) $base['in'];
		$e['avoided']['out'] += (int) $base['out'];
		$e['avoided_reason']  = sanitize_text_field( (string) $motivo );
		$e['last_at']         = time();
		if ( '' === $e['rel_path'] && '' !== self::$context['rel_path'] ) {
			$e['rel_path'] = self::$context['rel_path'];
		}

		$libro[ $key ] = $e;
		self::save( $libro );
		return $base;
	}

	/**
	 * Referencia de lo que cuesta un ciclo completo con modelo.
	 *
	 * @return array
	 */
	public static function baseline() {
		$libro = self::ledger();
		$in    = 0;
		$out   = 0;
		$n     = 0;
		foreach ( $libro as $e ) {
			if ( empty( $e['calls'] ) ) {
				continue;
			}
			$in += (int) $e['consumed']['in'];
			$out += (int) $e['consumed']['out'];
			$n++;
		}
		if ( $n < 3 ) {
			return array( 'in' => self::BASELINE_IN, 'out' => self::BASELINE_OUT, 'source' => 'referencia' );
		}
		return array(
			'in'     => (int) round( $in / $n ),
			'out'    => (int) round( $out / $n ),
			'source' => 'media_propia',
		);
	}

	/**
	 * Liquida una incidencia y congela lo facturable.
	 *
	 * @param string $key     Clave de la incidencia.
	 * @param string $outcome Desenlace.
	 * @return array Instantánea ya liquidada.
	 */
	public static function settle( $key, $outcome ) {
		$key     = sanitize_text_field( (string) $key );
		$outcome = sanitize_key( (string) $outcome );
		if ( '' === $key || ! in_array( $outcome, self::outcomes(), true ) ) {
			return self::snapshot( $key );
		}

		$libro = self::ledger();
		$e     = isset( $libro[ $key ] ) ? $libro[ $key ] : self::blank( $key );

		// Fail-closed: una liquidación no puede abaratarse sola. Una incidencia
		// ya cobrada como reparada solo puede cambiar a 'rolled_back', que es el
		// único desenlace posterior legítimo: se deshizo el cambio. Cualquier
		// otro intento de rebajarla se rechaza, venga de donde venga.
		if ( 'repaired' === $e['outcome'] && 'rolled_back' !== $outcome ) {
			return self::snapshot( $key );
		}
		// Y en general, liquidar de nuevo nunca puede reducir lo facturable
		// mientras el desenlace previo siga siendo válido.
		if ( '' !== $e['outcome'] && $outcome !== $e['outcome'] ) {
			$politica = self::policy();
			$antes    = isset( $politica['rates'][ $e['outcome'] ] ) ? (float) $politica['rates'][ $e['outcome'] ] : 0.0;
			$ahora    = isset( $politica['rates'][ $outcome ] ) ? (float) $politica['rates'][ $outcome ] : 0.0;
			if ( $ahora < $antes && 'rolled_back' !== $outcome ) {
				return self::snapshot( $key );
			}
		}

		$e['outcome']    = $outcome;
		$e['settled_at'] = time();
		$e['billable']   = self::billable_for( $e['consumed'], $outcome );

		$libro[ $key ] = $e;
		self::save( $libro );
		return self::snapshot( $key );
	}

	/**
	 * Calcula los tokens facturables de un consumo dado un desenlace.
	 *
	 * La franquicia se descuenta del total y el resto se reparte manteniendo
	 * la proporción entrada/salida, porque cada una tiene precio distinto.
	 *
	 * @param array  $consumed in, out.
	 * @param string $outcome  Desenlace.
	 * @return array
	 */
	public static function billable_for( $consumed, $outcome ) {
		$politica = self::policy();
		$in       = isset( $consumed['in'] ) ? max( 0, (int) $consumed['in'] ) : 0;
		$out      = isset( $consumed['out'] ) ? max( 0, (int) $consumed['out'] ) : 0;
		$total    = $in + $out;
		$tasa     = isset( $politica['rates'][ $outcome ] ) ? (float) $politica['rates'][ $outcome ] : 0.0;

		if ( $total <= 0 || $tasa <= 0.0 ) {
			return array( 'in' => 0, 'out' => 0 );
		}
		$sobre = max( 0, $total - (int) $politica['free_tokens'] );
		if ( $sobre <= 0 ) {
			return array( 'in' => 0, 'out' => 0 );
		}
		$ratio = ( $sobre * $tasa ) / $total;
		return array(
			'in'  => (int) round( $in * $ratio ),
			'out' => (int) round( $out * $ratio ),
		);
	}

	/**
	 * Estado de una incidencia, en el formato que consumen consola y reporte.
	 *
	 * @param string $key Clave de la incidencia.
	 * @return array
	 */
	public static function snapshot( $key ) {
		$key   = sanitize_text_field( (string) $key );
		$libro = self::ledger();
		$e     = ( '' !== $key && isset( $libro[ $key ] ) ) ? $libro[ $key ] : self::blank( $key );

		$politica  = self::policy();
		$consumido = (int) $e['consumed']['in'] + (int) $e['consumed']['out'];

		// Mientras está abierta se enseña lo que costaría si se aplicara: es
		// el número que hace falta para decidir, no uno optimista.
		$facturable = '' !== $e['outcome']
			? $e['billable']
			: self::billable_for( $e['consumed'], 'repaired' );

		return array(
			'key'            => $key,
			'rel_path'       => $e['rel_path'],
			'usage'          => array( 'in' => (int) $e['consumed']['in'], 'out' => (int) $e['consumed']['out'] ),
			'total'          => $consumido,
			'calls'          => (int) $e['calls'],
			'stages'         => is_array( $e['stages'] ) ? $e['stages'] : array(),
			'avoided'        => array( 'in' => (int) $e['avoided']['in'], 'out' => (int) $e['avoided']['out'] ),
			'avoided_total'  => (int) $e['avoided']['in'] + (int) $e['avoided']['out'],
			'avoided_reason' => (string) $e['avoided_reason'],
			'outcome'        => '' !== $e['outcome'] ? $e['outcome'] : 'open',
			'settled'        => '' !== $e['outcome'],
			'free_tokens'    => (int) $politica['free_tokens'],
			'free_left'      => max( 0, (int) $politica['free_tokens'] - $consumido ),
			'billable'       => array( 'in' => (int) $facturable['in'], 'out' => (int) $facturable['out'] ),
			'billable_total' => (int) $facturable['in'] + (int) $facturable['out'],
			'cost'           => ABH_Router::cost_label( array( 'in' => (int) $e['consumed']['in'], 'out' => (int) $e['consumed']['out'] ) ),
			'cost_billable'  => ABH_Router::cost_label( $facturable ),
			'label'          => self::label( $e, $facturable, $politica ),
		);
	}

	/**
	 * Frase que explica el estado del medidor en lenguaje claro.
	 *
	 * @param array $e          Entrada del libro.
	 * @param array $facturable Tokens facturables.
	 * @param array $politica   Política vigente.
	 * @return string
	 */
	private static function label( $e, $facturable, $politica ) {
		$consumido = (int) $e['consumed']['in'] + (int) $e['consumed']['out'];
		$evitado   = (int) $e['avoided']['in'] + (int) $e['avoided']['out'];

		if ( 0 === $consumido && $evitado > 0 ) {
			return __( 'Resolved without querying the model: 0 tokens.', 'ai-bug-hunter' );
		}
		if ( 0 === $consumido ) {
			return __( 'The model has not been consulted yet.', 'ai-bug-hunter' );
		}
		return sprintf(
			/* translators: %s: tokens used. */
			__( '%s tokens used. Any charge is determined by your configured AI provider and account.', 'ai-bug-hunter' ),
			number_format_i18n( $consumido )
		);
	}

	/**
	 * Añade el medidor a una respuesta que va al navegador.
	 *
	 * Sobrescribe a propósito usage_total y cost_total: el servidor manda, el
	 * navegador no acumula.
	 *
	 * @param array  $res Respuesta.
	 * @param string $key Clave de la incidencia. Vacío = la atribuida ahora.
	 * @return array
	 */
	public static function stamp( $res, $key = '' ) {
		if ( ! is_array( $res ) ) {
			return $res;
		}
		$key = '' !== $key ? $key : self::bound();
		if ( '' === $key ) {
			return $res;
		}
		$m = self::snapshot( $key );
		if ( 0 === $m['total'] && 0 === $m['avoided_total'] ) {
			return $res;
		}
		$res['meter']       = $m;
		$res['usage_total'] = $m['usage'];
		$res['cost_total']  = $m['cost'];
		return $res;
	}

	/**
	 * Serie diaria de consumo, para el mini-gráfico del escritorio.
	 *
	 * Agregado de solo lectura sobre el libro que ya existe: no guarda nada
	 * nuevo ni cambia una sola cifra. Cada incidencia aporta su consumo ENTERO
	 * al día de su última actividad, porque el libro guarda el total por
	 * incidencia y no un desglose por jornada. Eso es una aproximación y la
	 * pantalla tiene que decirlo con esas palabras: un gráfico que aparenta una
	 * precisión que no tiene es una cifra inventada con otra forma.
	 *
	 * @param int $dias Ventana en días, contando hoy.
	 * @return array Lista de array( 'd' => 'Y-m-d', 'v' => tokens ).
	 */
	public static function series( $dias = 14 ) {
		$dias = max( 2, min( 60, (int) $dias ) );

		// Se agrupa por el DÍA CIVIL del sitio, no por un offset fijo en
		// segundos. Con gmt_offset el horario de verano no se aplica hasta que
		// alguien vuelve a guardar los ajustes, y entonces lo que pasó a las
		// 23:30 aparece contado al día siguiente. wp_timezone() sí lo sigue.
		$zona = function_exists( 'wp_timezone' ) ? wp_timezone() : new DateTimeZone( 'UTC' );
		$hoy  = new DateTimeImmutable( 'now', $zona );

		$cubo = array();
		$sello = array();
		for ( $i = $dias - 1; $i >= 0; $i-- ) {
			$d              = $hoy->sub( new DateInterval( 'P' . $i . 'D' ) );
			$clave          = $d->format( 'Y-m-d' );
			$cubo[ $clave ] = 0;
			$sello[ $clave ] = $d->getTimestamp();
		}

		foreach ( self::ledger() as $e ) {
			$cuando = isset( $e['last_at'] ) ? (int) $e['last_at'] : 0;
			if ( $cuando <= 0 ) {
				continue;
			}
			$clave = ( new DateTimeImmutable( '@' . $cuando ) )->setTimezone( $zona )->format( 'Y-m-d' );
			if ( ! isset( $cubo[ $clave ] ) ) {
				continue;
			}
			$cubo[ $clave ] += (int) $e['consumed']['in'] + (int) $e['consumed']['out'];
		}

		$serie = array();
		foreach ( $cubo as $clave => $valor ) {
			$serie[] = array(
				'd'  => $clave,
				'ts' => $sello[ $clave ],
				'v'  => (int) $valor,
			);
		}
		return $serie;
	}

	/**
	 * Agregado global: lo que gastamos, lo que se factura y lo que se evitó.
	 *
	 * @return array
	 */
	public static function totals() {
		$libro = self::ledger();
		$t     = array(
			'incidents'     => 0,
			'consumed'      => array( 'in' => 0, 'out' => 0 ),
			'billable'      => array( 'in' => 0, 'out' => 0 ),
			'avoided'       => array( 'in' => 0, 'out' => 0 ),
			'deterministic' => 0,
			'by_outcome'    => array(),
		);
		foreach ( $libro as $e ) {
			$t['incidents']++;
			$t['consumed']['in']  += (int) $e['consumed']['in'];
			$t['consumed']['out'] += (int) $e['consumed']['out'];
			$t['avoided']['in']   += (int) $e['avoided']['in'];
			$t['avoided']['out']  += (int) $e['avoided']['out'];

			$outcome = '' !== $e['outcome'] ? $e['outcome'] : 'open';
			$fact    = '' !== $e['outcome'] ? $e['billable'] : array( 'in' => 0, 'out' => 0 );
			$t['billable']['in']  += (int) $fact['in'];
			$t['billable']['out'] += (int) $fact['out'];

			if ( ! isset( $t['by_outcome'][ $outcome ] ) ) {
				$t['by_outcome'][ $outcome ] = 0;
			}
			$t['by_outcome'][ $outcome ]++;

			if ( ( (int) $e['avoided']['in'] + (int) $e['avoided']['out'] ) > 0 && 0 === (int) $e['calls'] ) {
				$t['deterministic']++;
			}
		}
		$t['consumed_total'] = $t['consumed']['in'] + $t['consumed']['out'];
		$t['billable_total'] = $t['billable']['in'] + $t['billable']['out'];
		$t['avoided_total']  = $t['avoided']['in'] + $t['avoided']['out'];
		$t['cost_consumed']  = ABH_Router::cost_label( $t['consumed'] );
		$t['cost_billable']  = ABH_Router::cost_label( $t['billable'] );
		$t['cost_avoided']   = ABH_Router::cost_label( $t['avoided'] );
		return $t;
	}

	/**
	 * Entrada vacía del libro.
	 *
	 * @param string $key Clave.
	 * @return array
	 */
	private static function blank( $key ) {
		return array(
			'key'            => $key,
			'rel_path'       => '',
			'short'          => '',
			'consumed'       => array( 'in' => 0, 'out' => 0 ),
			'avoided'        => array( 'in' => 0, 'out' => 0 ),
			'avoided_reason' => '',
			'billable'       => array( 'in' => 0, 'out' => 0 ),
			'stages'         => array(),
			'jobs'           => array(),
			'calls'          => 0,
			'outcome'        => '',
			'reopened'       => 0,
			'first_at'       => time(),
			'last_at'        => time(),
			'settled_at'     => 0,
		);
	}

	/**
	 * Libro mayor completo, saneado.
	 *
	 * @return array
	 */
	public static function ledger() {
		if ( null !== self::$memo ) {
			return self::$memo;
		}
		$libro = get_option( self::OPTION, array() );
		if ( ! is_array( $libro ) ) {
			self::$memo = array();
			return array();
		}
		$limpio = array();
		foreach ( $libro as $k => $e ) {
			if ( ! is_array( $e ) || ! isset( $e['consumed'] ) || ! is_array( $e['consumed'] ) ) {
				continue;
			}
			$limpio[ (string) $k ] = array_merge( self::blank( (string) $k ), $e );
		}
		self::$memo = $limpio;
		return $limpio;
	}

	/**
	 * Guarda el libro recortado a las incidencias más recientes.
	 *
	 * @param array $libro Libro.
	 * @return void
	 */
	private static function save( $libro ) {
		if ( count( $libro ) > self::MAX_ENTRIES ) {
			uasort(
				$libro,
				function ( $a, $b ) {
					return (int) $b['last_at'] - (int) $a['last_at'];
				}
			);
			$libro = array_slice( $libro, 0, self::MAX_ENTRIES, true );
		}
		update_option( self::OPTION, $libro, false );
		self::$memo = null;
	}

	/**
	 * Borra el libro mayor.
	 *
	 * @return void
	 */
	public static function reset() {
		delete_option( self::OPTION );
		self::$memo = null;
	}

	/**
	 * Olvida el libro memorizado en esta petición.
	 *
	 * Dentro de una petición web solo nuestro propio save() cambia la opción,
	 * así que la memoria basta. En procesos largos (WP-CLI, cron de larga
	 * duración) la opción sí puede cambiar por fuera: ahí hay que llamarlo.
	 *
	 * @return void
	 */
	public static function flush_cache() {
		self::$memo = null;
	}
}
