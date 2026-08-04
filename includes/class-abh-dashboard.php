<?php
/**
 * Superficie visual de Diagnóstico.
 *
 * Esta clase solo prepara y presenta datos ya producidos por el motor.
 * No escanea, no repara y no escribe archivos.
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- The report exporter streams bounded data to avoid loading the complete archive into memory.

/**
 * Class ABH_Dashboard
 */
class ABH_Dashboard {

	/**
	 * Construye la fotografía ejecutiva del diagnóstico.
	 *
	 * @param array $activas      Incidencias activas.
	 * @param array $resueltas    Incidencias resueltas.
	 * @param array $informativas Avisos informativos.
	 * @param array $puente       Hallazgos de THOTH Security.
	 * @return array
	 */
	public static function data( $activas, $resueltas, $informativas, $puente, $ignored = 0 ) {
		$report   = ABH_Scanner::last_report();
		$syntax   = ABH_Scanner::fresh_findings( $report );
		$fatal    = 0;
		$warnings = 0;

		foreach ( $activas as $inc ) {
			$severity = isset( $inc['severity'] ) ? (int) $inc['severity'] : 0;
			$kind     = isset( $inc['kind'] ) ? strtolower( (string) $inc['kind'] ) : '';
			if ( $severity >= 90 || false !== strpos( $kind, 'fatal' ) || false !== strpos( $kind, 'parse' ) ) {
				$fatal++;
			} else {
				$warnings++;
			}
		}

		$pending = count( $activas ) + count( $syntax ) + count( $puente );
		$impact  = 'low';
		if ( count( $syntax ) > 0 || $fatal > 0 || count( $puente ) > 0 ) {
			$impact = 'high';
		} elseif ( $pending > 0 ) {
			$impact = 'medium';
		}

		$fingerprint = ! empty( $report )
			? hash( 'sha256', wp_json_encode( $report ) )
			: hash( 'sha256', ABH_VERSION . '|' . home_url( '/' ) );

		$journal = ABH_Backup::journal();
		$applied = 0;
		foreach ( $journal as $op ) {
			if ( isset( $op['status'] ) && in_array( $op['status'], array( 'applied', 'verified' ), true ) ) {
				$applied++;
			}
		}

		return array(
			'pending'       => $pending,
			'resolved'      => count( $resueltas ),
			'informational' => count( $informativas ),
			'ignored'       => max( 0, (int) $ignored ),
			'syntax'        => count( $syntax ),
			'fatal'         => $fatal,
			'warnings'      => $warnings,
			'bridge'        => count( $puente ),
			'scanned'       => isset( $report['scanned'] ) ? (int) $report['scanned'] : 0,
			'duration'      => isset( $report['duration'] ) ? (int) $report['duration'] : 0,
			'completed_at'  => isset( $report['completed_at'] ) ? (int) $report['completed_at'] : 0,
			'scan_id'       => isset( $report['scan_id'] ) ? (string) $report['scan_id'] : '',
			'scope'         => isset( $report['scope'] ) ? (string) $report['scope'] : '',
			'impact'        => $impact,
			'fingerprint'   => $fingerprint,
			'applied'       => $applied,
		);
	}

	/**
	 * Convierte todas las fuentes en una lista visual común.
	 *
	 * @param array $activas Incidencias activas de debug.log.
	 * @param array $puente  Hallazgos comunicados por THOTH Security.
	 * @return array
	 */
	public static function findings( $activas, $puente ) {
		$out    = array();
		$report = ABH_Scanner::last_report();

		foreach ( ABH_Scanner::fresh_findings( $report ) as $finding ) {
			$out[] = self::map_syntax( $finding );
		}
		foreach ( $puente as $finding ) {
			$out[] = self::map_bridge( $finding );
		}
		foreach ( $activas as $incident ) {
			$out[] = self::map_incident( $incident );
		}

		usort(
			$out,
			static function ( $a, $b ) {
				return (int) $b['severity'] <=> (int) $a['severity'];
			}
		);
		return array_values( $out );
	}

	/**
	 * Barra superior y cabecera ejecutiva.
	 *
	 * @param string $title Título.
	 * @param array  $data  Métricas.
	 * @return void
	 */
	public static function render_header( $title, $data ) {
		$session = ! empty( $data['scan_id'] ) ? $data['scan_id'] : 'BH-' . gmdate( 'Ymd-His' );
		$last    = ! empty( $data['completed_at'] ) ? sprintf( /* translators: %s: human-readable time difference. */ __( '%s ago', 'ai-bug-hunter' ), human_time_diff( (int) $data['completed_at'], time() ) ) : __( 'No scan', 'ai-bug-hunter' );
		?>
		<?php
		// Los avisos de WordPress van ARRIBA del todo, antes del encabezado de
		// Hunter. WordPress los inyecta donde quiere dentro de .wrap y acababan
		// partiendo la pantalla por la mitad; aquí tienen su sitio propio y no
		// compiten con el estado del diagnóstico.
		?>
		<div class="abh-notice-tray" id="abh-notice-tray" hidden>
			<button type="button" class="abh-notice-toggle" aria-expanded="false" aria-controls="abh-notice-tray-body">
				<span class="dashicons dashicons-megaphone" aria-hidden="true"></span><strong><?php esc_html_e( 'WordPress notices', 'ai-bug-hunter' ); ?></strong><span class="abh-notice-count">0</span><span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span>
			</button>
			<div class="abh-notice-tray-body" id="abh-notice-tray-body" hidden></div>
		</div>

		<?php
		// EL SEMÁFORO DEL MODO ROOT, en tres estados y en las dos barras.
		//
		// El servidor sólo conoce dos: armado o no. El tercero —«esperando tu
		// firma»— nace en la consola cuando aparece la pantalla de la frase, y
		// lo pinta el JS cambiando esta misma clase. Se declara aquí para que
		// las dos barras lean del mismo sitio y no acaben diciendo cosas
		// distintas sobre el mismo estado.
		//
		// Rojo NO significa «apagado»: significa que hay poder vivo ahora mismo.
		// Es lo que dice el §3 de la doctrina —«mientras está armado, consola en
		// rojo»—, y por eso el verde es el estado tranquilo y no el permisivo.
		$abh_armado = class_exists( 'ABH_Root' ) ? ABH_Root::armado() : false;
		$abh_luz    = $abh_armado ? 'is-rojo' : 'is-verde';
		$abh_luz_tx = $abh_armado
			? __( 'Root mode ARMED: a signed repair is in progress and writing is possible right now. It disarms itself when the plan finishes.', 'ai-bug-hunter' )
			: __( 'Normal state: it analyzes and proposes. It writes nothing without you signing it first.', 'ai-bug-hunter' );
		$abh_luz_et = $abh_armado ? __( 'Root armed', 'ai-bug-hunter' ) : __( 'Root idle', 'ai-bug-hunter' );
		?>
		<section class="abh-product-context <?php echo esc_attr( $abh_luz ); ?>" id="abh-product-context" data-root-armado="<?php echo $abh_armado ? '1' : '0'; ?>" aria-label="<?php esc_attr_e( 'Diagnosis context', 'ai-bug-hunter' ); ?>">
			<div class="abh-product-identity">
				<img src="<?php echo esc_url( ABH_URL . 'assets/brand/hunter-avatar.png' ); ?>" alt="">
				<div>
					<div class="abh-product-name"><strong><?php echo esc_html( ABH_PRODUCT_NAME ); ?></strong><span>v<?php echo esc_html( ABH_VERSION ); ?></span></div>
					<p><?php esc_html_e( 'AI for auditing, diagnosis and safe repair.', 'ai-bug-hunter' ); ?></p>
				</div>
			</div>
			<div class="abh-context-meta">
				<div><small><?php esc_html_e( 'SESSION', 'ai-bug-hunter' ); ?></small><strong><?php echo esc_html( $session ); ?></strong></div>
				<div><small><?php esc_html_e( 'ENVIRONMENT', 'ai-bug-hunter' ); ?></small><strong><?php echo esc_html( wp_parse_url( home_url( '/' ), PHP_URL_HOST ) ); ?></strong></div>
				<?php
				// La luz va acompañada SIEMPRE de su etiqueta en texto. Un punto
				// de color a solas no lo lee quien no distingue rojo de verde, y
				// éste es justo el dato que no se puede perder.
				?>
				<div class="is-route abh-luz-celda"><small><?php esc_html_e( 'SCOPE', 'ai-bug-hunter' ); ?></small>
					<strong><?php echo esc_html( 'full' === $data['scope'] ? __( 'Full WordPress', 'ai-bug-hunter' ) : __( 'Root, plugins and themes', 'ai-bug-hunter' ) ); ?></strong>
					<span class="abh-luz <?php echo esc_attr( $abh_luz ); ?>" data-abh-luz title="<?php echo esc_attr( $abh_luz_tx ); ?>"><i aria-hidden="true"></i><em data-abh-luz-texto><?php echo esc_html( $abh_luz_et ); ?></em></span>
				</div>
				<div class="abh-luz-celda"><small><?php esc_html_e( 'MODE', 'ai-bug-hunter' ); ?></small>
					<strong data-abh-modo-texto><?php esc_html_e( 'Analysis · Safe plan', 'ai-bug-hunter' ); ?></strong>
					<span class="abh-luz <?php echo esc_attr( $abh_luz ); ?>" data-abh-luz title="<?php echo esc_attr( $abh_luz_tx ); ?>"><i aria-hidden="true"></i><em data-abh-luz-texto><?php echo esc_html( $abh_luz_et ); ?></em></span>
				</div>
				<div><small><?php esc_html_e( 'LAST SCAN', 'ai-bug-hunter' ); ?></small><strong class="is-good"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><?php echo esc_html( $last ); ?></strong></div>
			</div>
			<div class="abh-context-actions">
				<button type="button" class="button abh-monitor-toggle" disabled title="<?php esc_attr_e( 'The continuous monitor control is not available yet in this build.', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-visibility" aria-hidden="true"></span><?php esc_html_e( 'Monitor active', 'ai-bug-hunter' ); ?></button>
				<button type="button" class="button abh-context-menu" aria-label="<?php esc_attr_e( 'More options', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-ellipsis" aria-hidden="true"></span></button>
			</div>
		</section>

		<section class="abh-diagnostic-hero">
			<?php self::render_consumo( $title ); ?>
			<?php self::render_header_stats( $data ); ?>
		</section>
		<?php
	}

	/**
	 * El consumo, donde antes había un texto que no decía nada.
	 *
	 * Esto NO es una gráfica, y es deliberado: el trabajo del dato es dar una
	 * magnitud de un vistazo, y para eso la forma correcta es un número grande
	 * con una barra de proporción debajo, no un chart con ejes. Lo que se pinta:
	 *
	 *  - Cuánto se ha gastado y lo que cuesta, en grande.
	 *  - La proporción entrada/salida, que es donde se va el dinero de verdad
	 *    (la salida cuesta varias veces más que la entrada en todos los
	 *    proveedores) y que nadie ve si sólo enseñas el total.
	 *  - Lo que NO se gastó porque lo resolvió un motor determinista. Ese dato
	 *    es el argumento del producto y estaba enterrado en el medidor.
	 *
	 * Cada segmento lleva su etiqueta y su cifra al lado: la identidad nunca
	 * depende sólo del color.
	 *
	 * @param string $title Título de la pantalla.
	 * @return void
	 */
	public static function render_consumo( $title ) {
		$t = class_exists( 'ABH_Meter' ) ? ABH_Meter::totals() : array();

		$in     = isset( $t['consumed']['in'] ) ? (int) $t['consumed']['in'] : 0;
		$out    = isset( $t['consumed']['out'] ) ? (int) $t['consumed']['out'] : 0;
		$total  = $in + $out;
		$ahorro = ( isset( $t['avoided']['in'] ) ? (int) $t['avoided']['in'] : 0 ) + ( isset( $t['avoided']['out'] ) ? (int) $t['avoided']['out'] : 0 );
		$incid  = isset( $t['incidents'] ) ? (int) $t['incidents'] : 0;
		$deter  = isset( $t['deterministic'] ) ? (int) $t['deterministic'] : 0;

		$coste = isset( $t['cost_consumed'] ) && '' !== $t['cost_consumed'] ? $t['cost_consumed'] : '';

		// Porcentajes con suelo visible: un segmento de 0.3 % que existe tiene
		// que verse, porque un tramo invisible se lee como «no hay nada ahí».
		$p_in  = $total > 0 ? max( 3, round( $in * 100 / $total ) ) : 0;
		$p_out = $total > 0 ? max( 3, 100 - $p_in ) : 0;
		?>
		<div class="abh-consumo" role="group" aria-label="<?php esc_attr_e( 'Token usage', 'ai-bug-hunter' ); ?>">
			<?php
			// Sin mascota en esta zona. Hunter ya está en el encabezado del
			// producto, dos centímetros más arriba: repetirlo aquí no añade
			// nada y le roba sitio al dato, que es lo que se viene a mirar.
			?>
			<div class="abh-consumo-cab is-sin-mascota">
				<div>
					<h1><?php echo esc_html( $title ); ?></h1>
					<p><?php esc_html_e( 'Engine usage', 'ai-bug-hunter' ); ?></p>
				</div>
			</div>

			<div class="abh-consumo-cifra">
				<strong data-abh-count="<?php echo (int) $total; ?>"><?php echo esc_html( number_format_i18n( $total ) ); ?></strong>
				<span><?php esc_html_e( 'tokens', 'ai-bug-hunter' ); ?><?php echo '' !== $coste ? ' · ' . esc_html( $coste ) : ''; ?></span>
			</div>

			<?php if ( $total > 0 ) : ?>
				<div class="abh-consumo-barra" aria-hidden="true">
					<span class="is-in" style="width:<?php echo (int) $p_in; ?>%"></span>
					<span class="is-out" style="width:<?php echo (int) $p_out; ?>%"></span>
				</div>
				<ul class="abh-consumo-leyenda">
					<li><i class="is-in" aria-hidden="true"></i><?php esc_html_e( 'Input', 'ai-bug-hunter' ); ?> <b><?php echo esc_html( number_format_i18n( $in ) ); ?></b></li>
					<li><i class="is-out" aria-hidden="true"></i><?php esc_html_e( 'Output', 'ai-bug-hunter' ); ?> <b><?php echo esc_html( number_format_i18n( $out ) ); ?></b></li>
				</ul>
				<?php self::render_consumo_spark(); ?>
			<?php else : ?>
				<p class="abh-consumo-vacio"><?php esc_html_e( 'Nothing has been spent yet. Quick scans and deterministic engines do not use tokens.', 'ai-bug-hunter' ); ?></p>
			<?php endif; ?>

			<?php if ( $ahorro > 0 ) : ?>
				<p class="abh-consumo-ahorro">
					<span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
					<?php
					printf(
						/* translators: 1: tokens ahorrados, 2: número de incidencias resueltas sin IA. */
						esc_html__( '%1$s tokens that were not spent: %2$s were resolved with deterministic engines.', 'ai-bug-hunter' ),
						'<b>' . esc_html( number_format_i18n( $ahorro ) ) . '</b>',
						'<b>' . esc_html( number_format_i18n( $deter ) ) . '</b>'
					);
					?>
				</p>
			<?php endif; ?>

			<?php if ( $incid > 0 ) : ?>
				<p class="abh-consumo-pie">
					<?php
					printf(
						/* translators: %s: número de incidencias contadas. */
						esc_html__( 'Counted by cause, not by occurrence: %s issues in the ledger.', 'ai-bug-hunter' ),
						esc_html( number_format_i18n( $incid ) )
					);
					?>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Mini-gráfico de consumo de los últimos catorce días.
	 *
	 * Se dibuja en el servidor, en SVG plano y sin una sola librería: así el
	 * gráfico existe aunque el JavaScript no cargue, que es exactamente el
	 * momento en que alguien viene a mirar por qué algo va mal. El JS solo le
	 * anima el trazo; si no llega, se ve igual, quieto.
	 *
	 * Si en la ventana no se gastó nada no se pinta nada: una línea plana en
	 * cero ocupa sitio para decir lo mismo que el texto de al lado.
	 *
	 * @return void
	 */
	private static function render_consumo_spark() {
		if ( ! class_exists( 'ABH_Meter' ) || ! method_exists( 'ABH_Meter', 'series' ) ) {
			return;
		}
		$serie = ABH_Meter::series( 14 );
		$vals  = wp_list_pluck( $serie, 'v' );
		$max   = $vals ? max( $vals ) : 0;
		if ( $max <= 0 || count( $vals ) < 2 ) {
			return;
		}

		$ancho  = 240;
		$alto   = 38;
		$paso   = $ancho / ( count( $vals ) - 1 );
		$puntos = array();
		foreach ( $vals as $i => $v ) {
			$x        = round( $i * $paso, 2 );
			$y        = round( $alto - ( $v * ( $alto - 4 ) / $max ) - 2, 2 );
			$puntos[] = $x . ',' . $y;
		}
		$linea = implode( ' ', $puntos );
		$area  = '0,' . $alto . ' ' . $linea . ' ' . $ancho . ',' . $alto;

		// array_search devuelve el PRIMER indice si el maximo se repite. Da igual
		// cual se nombre —el valor es el mismo—, pero conviene que sea estable.
		$pico  = (int) array_search( $max, $vals, true );
		$ts    = isset( $serie[ $pico ]['ts'] ) ? (int) $serie[ $pico ]['ts'] : 0;
		$dia   = $ts && function_exists( 'wp_date' )
			? wp_date( (string) get_option( 'date_format', 'Y-m-d' ), $ts )
			: ( isset( $serie[ $pico ]['d'] ) ? $serie[ $pico ]['d'] : '' );
		$resum = sprintf(
			/* translators: 1: tokens del día de mayor consumo, 2: fecha de ese día. */
			__( 'Daily usage over the last 14 days. Peak: %1$s tokens on %2$s.', 'ai-bug-hunter' ),
			number_format_i18n( $max ),
			$dia
		);
		?>
		<figure class="abh-consumo-spark">
			<svg viewBox="0 0 <?php echo (int) $ancho; ?> <?php echo (int) $alto; ?>" preserveAspectRatio="none" role="img" aria-label="<?php echo esc_attr( $resum ); ?>" focusable="false">
				<defs>
					<linearGradient id="abh-spark-g" x1="0" y1="0" x2="0" y2="1">
						<stop offset="0%" stop-color="#1769e8" stop-opacity=".26"/>
						<stop offset="100%" stop-color="#1769e8" stop-opacity="0"/>
					</linearGradient>
				</defs>
				<polygon points="<?php echo esc_attr( $area ); ?>" fill="url(#abh-spark-g)"/>
				<polyline points="<?php echo esc_attr( $linea ); ?>" fill="none" stroke="#1769e8" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
			</svg>
			<figcaption>
				<?php
				esc_html_e( 'Usage per day · 14 days. Each issue counts in full on the day of its last activity, which is the detail the ledger keeps.', 'ai-bug-hunter' );
				?>
			</figcaption>
		</figure>
		<?php
	}

	/**
	 * Indicadores superiores.
	 *
	 * @param array $data Métricas.
	 * @return void
	 */
	public static function render_header_stats( $data ) {
		// El chip permanente. No se cierra, no se descarta y no depende de que
		// nadie haya leído la bienvenida: quien entra a esta pantalla ve qué
		// tiene delante. Declarar la capacidad es lo que nos permite
		// conservarla.
		// La franja grande se retiró de aquí: ocupaba media pantalla repitiendo
		// en cada carga algo que ya está declarado. La capacidad NO deja de
		// anunciarse —eso sería recortar la doctrina en silencio—: vive ahora en
		// el semáforo de las celdas ALCANCE y MODO, con su luz, su etiqueta en
		// texto y el detalle completo en el título emergente. Se ve siempre y
		// deja de estorbar, que era el problema real.
		$cards = array(
			array( 'pending', 'danger', 'dashicons-warning', __( 'Pending', 'ai-bug-hunter' ), __( 'Need attention', 'ai-bug-hunter' ) ),
			array( 'resolved', 'success', 'dashicons-shield-alt', __( 'Resolved', 'ai-bug-hunter' ), __( 'Problems fixed', 'ai-bug-hunter' ) ),
			array( 'ignored', 'muted', 'dashicons-dismiss', __( 'Ignored', 'ai-bug-hunter' ), __( 'Intentionally excluded', 'ai-bug-hunter' ) ),
		);

		// El contador de tokens ya NO es una cuarta tarjeta. No desapareció de la
		// pantalla —eso fue el error de una vez y el reporte que llegó no fue
		// «está en cero» sino «lo borraste»—: ascendió al bloque de consumo de la
		// izquierda, donde además de la cifra se ve el reparto entrada/salida y
		// lo que los motores deterministas ahorraron. Más sitio, no menos.
		?>
		<div class="abh-hero-stats">
			<?php foreach ( $cards as $card ) : ?>
				<?php $abh_n = isset( $data[ $card[0] ] ) ? (int) $data[ $card[0] ] : 0; ?>
				<div class="abh-hero-stat is-<?php echo esc_attr( $card[1] ); ?>"><span class="dashicons <?php echo esc_attr( $card[2] ); ?>" aria-hidden="true"></span><div><b><?php echo esc_html( $card[3] ); ?></b><strong data-abh-count="<?php echo (int) $abh_n; ?>"><?php echo esc_html( number_format_i18n( $abh_n ) ); ?></strong><small><?php echo esc_html( $card[4] ); ?></small></div></div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Hallazgo principal con navegación entre incidencias.
	 *
	 * @param array $findings Hallazgos normalizados.
	 * @return void
	 */
	public static function render_finding_workspace( $findings ) {
		$count = count( $findings );
		?>
		<section class="abh-finding-workspace" data-finding-count="<?php echo esc_attr( $count ); ?>">
			<header class="abh-finding-toolbar">
				<div><strong><?php esc_html_e( 'Main finding', 'ai-bug-hunter' ); ?></strong><?php if ( $count > 0 ) : ?><span class="abh-severity-pill is-<?php echo esc_attr( $findings[0]['tone'] ); ?>" data-active-severity><?php echo esc_html( $findings[0]['severity_label'] ); ?></span><?php endif; ?></div>
				<?php if ( $count > 0 ) : ?><div class="abh-finding-nav"><span><b data-finding-current>1</b> <?php esc_html_e( 'of', 'ai-bug-hunter' ); ?> <?php echo esc_html( $count ); ?></span><button type="button" class="button abh-finding-prev" aria-label="<?php esc_attr_e( 'Previous finding', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-arrow-left-alt2"></span></button><button type="button" class="button abh-finding-next" aria-label="<?php esc_attr_e( 'Next finding', 'ai-bug-hunter' ); ?>"><span class="dashicons dashicons-arrow-right-alt2"></span></button></div><?php endif; ?>
			</header>
			<div class="abh-finding-stage">
				<?php if ( empty( $findings ) ) : ?>
					<div class="abh-clean-state"><span class="dashicons dashicons-shield-alt"></span><div><h2><?php esc_html_e( 'There are no active findings', 'ai-bug-hunter' ); ?></h2><p><?php esc_html_e( 'The scope reviewed contains no pending errors. You can run a full scan to widen the check.', 'ai-bug-hunter' ); ?></p></div></div>
				<?php else : ?>
					<?php foreach ( $findings as $index => $finding ) : ?>
						<article class="abh-finding-slide abh-incident" data-finding-index="<?php echo esc_attr( $index ); ?>" data-key="<?php echo esc_attr( $finding['key'] ); ?>" data-finding-tone="<?php echo esc_attr( $finding['tone'] ); ?>" data-finding-severity="<?php echo esc_attr( $finding['severity_label'] ); ?>" <?php echo 0 === $index ? '' : 'hidden'; ?>>
							<div class="abh-finding-file"><span class="dashicons dashicons-media-code"></span><code><?php echo esc_html( $finding['rel'] ); ?></code><?php if ( $finding['line'] ) : ?><span><?php echo esc_html( sprintf( /* translators: %d: source code line number. */ __( 'Line %d', 'ai-bug-hunter' ), $finding['line'] ) ); ?></span><?php endif; ?><?php if ( 'bridge' !== $finding['source'] && '' !== $finding['key'] ) : ?><button type="button" class="button-link abh-dismiss" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><?php esc_html_e( 'Hide', 'ai-bug-hunter' ); ?></button><?php endif; ?></div>
							<h2><?php echo esc_html( $finding['title'] ); ?></h2>
							<p class="abh-finding-summary"><?php echo esc_html( $finding['summary'] ); ?></p>
							<?php if ( ! empty( $finding['detail'] ) && $finding['detail'] !== $finding['summary'] ) : ?><p class="abh-finding-detail"><?php echo esc_html( $finding['detail'] ); ?></p><?php endif; ?>
							<div class="abh-recommendation">
								<div class="abh-recommendation-copy"><span class="dashicons dashicons-lightbulb"></span><div><strong><?php esc_html_e( 'Recommendation', 'ai-bug-hunter' ); ?></strong><p><?php echo esc_html( $finding['recommendation'] ); ?></p></div></div>
								<?php if ( ! empty( $finding['source_line'] ) ) : ?><div class="abh-code-line"><span><?php echo esc_html( $finding['line'] ); ?></span><code><?php echo esc_html( $finding['source_line'] ); ?></code></div><?php endif; ?>
							</div>
							<div class="abh-finding-actions">
								<?php self::render_finding_actions( $finding ); ?>
							</div>
							<div class="abh-result" style="display:none"></div>
						</article>
					<?php endforeach; ?>
				<?php endif; ?>
			</div>
		</section>
		<?php
	}

	/**
	 * Contexto lateral sincronizado con el hallazgo visible.
	 *
	 * @param array $data     Métricas.
	 * @param array $findings Hallazgos.
	 * @return void
	 */
	public static function render_sidebar( $data, $findings = array() ) {
		?>
		<aside class="abh-diagnostic-sidebar">
			<section class="abh-side-card"><h2><span class="dashicons dashicons-media-document"></span><?php esc_html_e( 'Diagnosis summary', 'ai-bug-hunter' ); ?></h2><dl class="abh-summary-list"><div><dt><?php esc_html_e( 'Files analyzed', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( $data['scanned'] ) ); ?></dd></div><div><dt><?php esc_html_e( 'Problems detected', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( $data['pending'] ) ); ?></dd></div><div><dt><?php esc_html_e( 'Warnings', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( $data['warnings'] ) ); ?></dd></div><div><dt><?php esc_html_e( 'Syntax errors', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( number_format_i18n( $data['syntax'] ) ); ?></dd></div><div><dt><?php esc_html_e( 'Total time', 'ai-bug-hunter' ); ?></dt><dd><?php echo esc_html( self::duration( $data['duration'] ) ); ?></dd></div></dl></section>
			<?php if ( empty( $findings ) ) : ?>
				<section class="abh-side-card is-success"><h2><span class="dashicons dashicons-yes-alt"></span><?php esc_html_e( 'Current status', 'ai-bug-hunter' ); ?></h2><p><?php esc_html_e( 'There is no active cause to explain. The system remains under observation with no changes applied.', 'ai-bug-hunter' ); ?></p></section>
			<?php else : ?>
				<?php foreach ( $findings as $index => $finding ) : ?>
					<div class="abh-context-set" data-context-index="<?php echo esc_attr( $index ); ?>" <?php echo 0 === $index ? '' : 'hidden'; ?>>
						<section class="abh-side-card"><h2><span class="dashicons dashicons-admin-site-alt3"></span><?php esc_html_e( 'Likely cause', 'ai-bug-hunter' ); ?></h2><p><?php echo esc_html( $finding['cause'] ); ?></p></section>
						<section class="abh-side-card"><h2><span class="dashicons dashicons-admin-tools"></span><?php esc_html_e( 'Suggested actions', 'ai-bug-hunter' ); ?></h2><ul class="abh-action-list"><?php foreach ( array_slice( $finding['steps'], 0, 4 ) as $step ) : ?><li><?php echo esc_html( $step ); ?></li><?php endforeach; ?></ul></section>
						<section class="abh-side-card abh-risk-card is-<?php echo esc_attr( $finding['risk'] ); ?>"><h2><span class="dashicons dashicons-shield"></span><?php esc_html_e( 'Current risk', 'ai-bug-hunter' ); ?><strong><?php echo esc_html( self::impact_label( $finding['risk'] ) ); ?></strong></h2><ul><li><?php echo esc_html( sprintf( /* translators: %s: finding severity label. */ __( 'Type: %s', 'ai-bug-hunter' ), $finding['severity_label'] ) ); ?></li><li><?php echo esc_html( sprintf( /* translators: %s: finding source label. */ __( 'Source: %s', 'ai-bug-hunter' ), $finding['source_label'] ) ); ?></li><li><?php echo esc_html( $finding['impact'] ); ?></li></ul></section>
					</div>
				<?php endforeach; ?>
			<?php endif; ?>
		</aside>
		<?php
	}

	/**
	 * Barra inferior de estado.
	 *
	 * @param array $data Métricas.
	 * @return void
	 */
	public static function render_statusbar( $data ) {
		$clean = 0 === (int) $data['pending'];
		?>
		<footer class="abh-statusbar">
			<div class="abh-status-item is-integrity"><span class="dashicons dashicons-shield-alt"></span><div><small><?php esc_html_e( 'System integrity', 'ai-bug-hunter' ); ?></small><strong><?php echo esc_html( $clean ? __( 'OK', 'ai-bug-hunter' ) : __( 'Needs attention', 'ai-bug-hunter' ) ); ?></strong><span><?php echo esc_html( $clean ? __( 'All modules operational', 'ai-bug-hunter' ) : __( 'There are pending items', 'ai-bug-hunter' ) ); ?></span></div></div>
			<div class="abh-status-item"><span class="dashicons dashicons-id"></span><div><small><?php esc_html_e( 'File fingerprints', 'ai-bug-hunter' ); ?></small><strong><code><?php echo esc_html( 'sha256: ' . substr( $data['fingerprint'], 0, 12 ) . '…' . substr( $data['fingerprint'], -12 ) ); ?></code></strong><span><?php esc_html_e( 'Verifiable snapshot of the analysis', 'ai-bug-hunter' ); ?></span></div></div>
			<div class="abh-status-item"><span class="dashicons dashicons-editor-code"></span><div><small><?php esc_html_e( 'Current mode', 'ai-bug-hunter' ); ?></small><strong class="is-mode"><?php esc_html_e( 'DRY-RUN', 'ai-bug-hunter' ); ?></strong><span><?php esc_html_e( 'Analysis only, no modifications', 'ai-bug-hunter' ); ?></span></div></div>
			<div class="abh-status-item"><span class="dashicons dashicons-randomize"></span><div><small><?php esc_html_e( 'Changes', 'ai-bug-hunter' ); ?></small><strong><?php echo esc_html( $data['applied'] > 0 ? sprintf( /* translators: %d: number of applied changes. */ _n( '%d applied', '%d applied', $data['applied'], 'ai-bug-hunter' ), $data['applied'] ) : __( 'No changes applied', 'ai-bug-hunter' ) ); ?></strong><span><?php esc_html_e( 'The system remains intact', 'ai-bug-hunter' ); ?></span></div></div>
			<div class="abh-status-item is-hunter"><img src="<?php echo esc_url( ABH_URL . 'assets/brand/hunter-avatar.png' ); ?>" alt=""><div><small><?php esc_html_e( 'Hunter is learning.', 'ai-bug-hunter' ); ?></small><strong><?php esc_html_e( 'Improving its red team thinking.', 'ai-bug-hunter' ); ?></strong></div><a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=' . ABH_SLUG . '-historial' ) ); ?>"><?php esc_html_e( 'View history', 'ai-bug-hunter' ); ?></a></div>
		</footer>
		<?php
	}

	/**
	 * Acciones compatibles con los manejadores existentes.
	 *
	 * @param array $finding Hallazgo.
	 * @return void
	 */
	private static function render_finding_actions( $finding ) {
		if ( 'bridge' === $finding['source'] ) {
			?><button class="button button-primary abh-guard-fix" data-rel="<?php echo esc_attr( $finding['rel'] ); ?>"><span class="dashicons dashicons-admin-tools"></span><?php esc_html_e( 'Repair in the console (no tokens)', 'ai-bug-hunter' ); ?></button><?php
			return;
		}
		if ( ! empty( $finding['motor_fixable'] ) ) {
			?><button class="button button-primary abh-env-fix" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><span class="dashicons dashicons-admin-tools"></span><?php esc_html_e( 'Review and fix in console', 'ai-bug-hunter' ); ?></button><?php
			if ( empty( $finding['protected'] ) ) {
				?><button class="button abh-analyze" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><?php esc_html_e( 'Review with HUNTER AI', 'ai-bug-hunter' ); ?></button><?php
			}
			return;
		}
		if ( ! empty( $finding['protected'] ) ) {
			if ( ! empty( $finding['core'] ) ) {
				?><div class="abh-core-file" data-file="<?php echo esc_attr( $finding['rel'] ); ?>" data-fn="<?php echo esc_attr( $finding['undefined_function'] ); ?>"><button type="button" class="button abh-core-diff"><?php esc_html_e( 'Compare with WordPress', 'ai-bug-hunter' ); ?></button><button type="button" class="button-link abh-core-restore"><?php esc_html_e( 'Restore official', 'ai-bug-hunter' ); ?></button><div class="abh-core-diffbox"></div></div><?php
			}
			?><button class="button abh-advise" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><?php esc_html_e( 'Tell me how to fix it myself', 'ai-bug-hunter' ); ?></button><?php
			return;
		}
		?><button class="button button-primary abh-advise" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><span class="dashicons dashicons-admin-tools"></span><?php esc_html_e( 'Tell me how to fix it myself', 'ai-bug-hunter' ); ?></button><button class="button abh-analyze" data-key="<?php echo esc_attr( $finding['key'] ); ?>"><span class="dashicons dashicons-media-code"></span><?php esc_html_e( 'Prepare repair', 'ai-bug-hunter' ); ?></button><?php
	}

	/**
	 * @param array $finding Hallazgo sintáctico.
	 * @return array
	 */
	private static function map_syntax( $finding ) {
		$rel  = isset( $finding['rel_path'] ) ? (string) $finding['rel_path'] : '';
		$line = isset( $finding['line'] ) ? (int) $finding['line'] : 0;
		$core = ! empty( $finding['core_file'] ) || ABH_Scanner::is_core_file( $rel );
		return array(
			'source'             => 'syntax',
			'source_label'       => __( 'Local scanner', 'ai-bug-hunter' ),
			'key'                 => isset( $finding['key'] ) ? (string) $finding['key'] : '',
			'rel'                 => $rel,
			'line'                => $line,
			'severity'            => 100,
			'severity_label'      => __( 'SYNTAX', 'ai-bug-hunter' ),
			'tone'                => 'fatal',
			'title'               => __( 'PHP cannot interpret this file', 'ai-bug-hunter' ),
			'summary'             => isset( $finding['short'] ) ? (string) $finding['short'] : __( 'A syntax error was detected.', 'ai-bug-hunter' ),
			'detail'              => __( 'The file fails before it can run. A screen, a plugin, or all of WordPress may stop loading.', 'ai-bug-hunter' ),
			'recommendation'      => $core ? __( 'Do not modify a core file automatically. Compare it with the original from the same WordPress version.', 'ai-bug-hunter' ) : __( 'Fix the syntax and validate the file with the PHP parser before loading it again.', 'ai-bug-hunter' ),
			'cause'               => __( 'There is an invalid structure, an unexpected token or an unclosed delimiter in the flagged file.', 'ai-bug-hunter' ),
			'steps'               => array( __( 'Open the line indicated and review the block right around it.', 'ai-bug-hunter' ), __( 'Prepare a minimal, reversible change.', 'ai-bug-hunter' ), __( 'Validate the file with the PHP parser.', 'ai-bug-hunter' ), __( 'Run a full scan again.', 'ai-bug-hunter' ) ),
			'risk'                => 'high',
			'impact'              => __( 'Impact: partial or total interruption of WordPress loading.', 'ai-bug-hunter' ),
			'source_line'         => self::source_line( $rel, $line ),
			'protected'           => $core,
			'core'                => $core,
			'motor_fixable'       => false,
			'undefined_function'  => '',
		);
	}

	/**
	 * @param array $finding Hallazgo de seguridad.
	 * @return array
	 */
	private static function map_bridge( $finding ) {
		$rel = isset( $finding['rel_path'] ) ? (string) $finding['rel_path'] : '';
		return array(
			'source'            => 'bridge',
			'source_label'      => __( 'THOTH Security', 'ai-bug-hunter' ),
			'key'               => isset( $finding['key'] ) ? (string) $finding['key'] : 'bridge-' . md5( $rel ),
			'rel'               => $rel,
			'line'              => 1,
			'severity'          => 95,
			'severity_label'    => __( 'HIGH', 'ai-bug-hunter' ),
			'tone'              => 'fatal',
			'title'             => __( 'PHP file directly accessible from the browser', 'ai-bug-hunter' ),
			'summary'           => __( 'The file can run without WordPress having loaded its protections.', 'ai-bug-hunter' ),
			'detail'            => __( 'This can reveal internal server paths or produce errors outside the plugin\'s normal context.', 'ai-bug-hunter' ),
			'recommendation'    => __( 'Add an ABSPATH guard at the top of the file and check HTTP access again.', 'ai-bug-hunter' ),
			'cause'             => __( 'The file does not stop execution when it is requested directly.', 'ai-bug-hunter' ),
			'steps'             => array( __( 'Prepare a deterministic change that can be verified before applying it.', 'ai-bug-hunter' ), __( 'Add the guard without changing the logic of the file.', 'ai-bug-hunter' ), __( 'Check syntax.', 'ai-bug-hunter' ), __( 'Run the security scan again.', 'ai-bug-hunter' ) ),
			'risk'              => 'high',
			'impact'            => __( 'Impact: exposure of internal paths and execution out of context.', 'ai-bug-hunter' ),
			'source_line'       => self::source_line( $rel, 1 ),
			'protected'         => false,
			'core'              => false,
			'motor_fixable'     => false,
			'undefined_function'=> '',
		);
	}

	/**
	 * @param array $incident Incidencia del registro.
	 * @return array
	 */
	private static function map_incident( $incident ) {
		$rel      = isset( $incident['rel_path'] ) ? (string) $incident['rel_path'] : '';
		$line     = isset( $incident['line'] ) ? (int) $incident['line'] : 0;
		$severity = isset( $incident['severity'] ) ? (int) $incident['severity'] : 50;
		$fatal    = ABH_Motor::is_fatal_incident( $incident );
		$motor    = ABH_Motor::diagnose( $incident );
		$check    = '' !== $rel ? ABH_Guard::check_path( $rel, ABH_Engine::writable_roots() ) : array( 'allowed' => false );
		$protected = empty( $check['allowed'] );
		$core      = '' !== $rel && ABH_Scanner::is_core_file( $rel );
		$title     = is_array( $motor ) && ! empty( $motor['titulo'] ) ? (string) $motor['titulo'] : self::generic_title( $incident );
		$summary   = isset( $incident['short'] ) ? (string) $incident['short'] : '';
		$detail    = is_array( $motor ) && ! empty( $motor['diagnosis'] ) ? (string) $motor['diagnosis'] : ( isset( $incident['message'] ) ? (string) $incident['message'] : $summary );
		$steps     = is_array( $motor ) && ! empty( $motor['steps'] ) ? array_values( $motor['steps'] ) : array( __( 'Confirm that the file and the line still correspond to the error.', 'ai-bug-hunter' ), __( 'Review the evidence before proposing code.', 'ai-bug-hunter' ), __( 'Prepare a minimal, reversible diff.', 'ai-bug-hunter' ), __( 'Validate the result with a new scan.', 'ai-bug-hunter' ) );
		return array(
			'source'             => 'log',
			'source_label'       => __( 'PHP log', 'ai-bug-hunter' ),
			'key'                 => isset( $incident['key'] ) ? (string) $incident['key'] : '',
			'rel'                 => '' !== $rel ? $rel : __( 'Unidentified file', 'ai-bug-hunter' ),
			'line'                => $line,
			'severity'            => $severity,
			'severity_label'      => $fatal ? __( 'FATAL', 'ai-bug-hunter' ) : __( 'NOTICE', 'ai-bug-hunter' ),
			'tone'                => $fatal ? 'fatal' : 'warning',
			'title'               => $title,
			'summary'             => $summary,
			'detail'              => $detail,
			'recommendation'      => is_array( $motor ) && ! empty( $motor['explicacion'] ) ? (string) $motor['explicacion'] : __( 'Gathers evidence from the deployed file and reviews a change proposal before authorizing any modification.', 'ai-bug-hunter' ),
			'cause'               => $detail,
			'steps'               => $steps,
			'risk'                => $fatal ? 'high' : 'medium',
			'impact'              => $fatal ? __( 'Impact: the request may stop and leave a feature or the whole site unresponsive.', 'ai-bug-hunter' ) : __( 'Impact: degradation of a specific feature or more errors in the log.', 'ai-bug-hunter' ),
			'source_line'         => self::source_line( $rel, $line ),
			'protected'           => $protected,
			'core'                => $core,
			'motor_fixable'       => is_array( $motor ) && ! empty( $motor['fixable'] ),
			'undefined_function'  => class_exists( 'ABH_Core' ) ? ABH_Core::undefined_function_in( $summary ) : '',
		);
	}

	/**
	 * Título genérico honesto cuando el motor no reconoce la firma.
	 *
	 * @param array $incident Incidencia.
	 * @return string
	 */
	private static function generic_title( $incident ) {
		$kind = isset( $incident['kind'] ) ? strtolower( (string) $incident['kind'] ) : '';
		if ( false !== strpos( $kind, 'fatal' ) ) {
			return __( 'PHP fatal error', 'ai-bug-hunter' );
		}
		if ( false !== strpos( $kind, 'warning' ) ) {
			return __( 'PHP warning', 'ai-bug-hunter' );
		}
		if ( false !== strpos( $kind, 'notice' ) ) {
			return __( 'PHP notice', 'ai-bug-hunter' );
		}
		return __( 'Issue detected in the log', 'ai-bug-hunter' );
	}

	/**
	 * Lee una sola línea segura de wp-content para contexto visual.
	 *
	 * @param string $rel  Ruta relativa.
	 * @param int    $line Línea.
	 * @return string
	 */
	private static function source_line( $rel, $line ) {
		$rel  = wp_normalize_path( (string) $rel );
		$line = (int) $line;
		if ( $line < 1 || 0 !== strpos( $rel, 'wp-content/' ) || false !== stripos( $rel, 'wp-config.php' ) ) {
			return '';
		}
		$abs  = wp_normalize_path( ABSPATH . ltrim( $rel, '/' ) );
		$real = @realpath( $abs );
		$root = @realpath( WP_CONTENT_DIR );
		if ( ! $real || ! $root || 0 !== strpos( wp_normalize_path( $real ), wp_normalize_path( $root ) ) || ! is_readable( $real ) ) {
			return '';
		}
		$fh = @fopen( $real, 'rb' );
		if ( ! $fh ) {
			return '';
		}
		$current = 0;
		$value   = '';
		while ( ! feof( $fh ) && $current < $line ) {
			$current++;
			$chunk = fgets( $fh );
			if ( $current === $line ) {
				$value = is_string( $chunk ) ? trim( $chunk ) : '';
				break;
			}
		}
		fclose( $fh );
		return function_exists( 'mb_substr' ) ? mb_substr( $value, 0, 320 ) : substr( $value, 0, 320 );
	}

	/**
	 * @param int $seconds Segundos.
	 * @return string
	 */
	private static function duration( $seconds ) {
		$seconds = max( 0, (int) $seconds );
		if ( $seconds < 60 ) {
			return sprintf( /* translators: %d: duration in seconds. */ __( '%d s', 'ai-bug-hunter' ), $seconds );
		}
		return sprintf( /* translators: 1: whole minutes, 2: remaining seconds. */ __( '%1$d min %2$d s', 'ai-bug-hunter' ), floor( $seconds / 60 ), $seconds % 60 );
	}

	/**
	 * @param string $impact Nivel.
	 * @return string
	 */
	private static function impact_label( $impact ) {
		if ( 'high' === $impact ) {
			return __( 'High', 'ai-bug-hunter' );
		}
		if ( 'medium' === $impact ) {
			return __( 'Medium', 'ai-bug-hunter' );
		}
		return __( 'Low', 'ai-bug-hunter' );
	}
}
