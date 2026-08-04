<?php
/**
 * Artefactos descargables de HUNTER AI.
 *
 * Genera reportes HTML autocontenidos y paquetes de reparación revisables.
 * Ningún archivo se publica bajo uploads: los artefactos se construyen en un
 * temporal privado, se entregan al administrador y se eliminan de inmediato.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Empaqueta código del sitio en un ZIP descargable.
 *
 * POR QUE EXISTE:  El expediente completo es lo que permite auditar lo que hizo el plugin.
 *
 * SI LO RECORTAS:  El base64 de este archivo es transporte de un ZIP por AJAX. No decodifica NADA que venga de fuera: si algún día aparece aquí una decodificación de contenido externo, es un fallo.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Artifact cleanup targets only normalized plugin-owned temporary paths and must set restrictive local permissions.

/**
 * Class ABH_Artifacts
 */
class ABH_Artifacts {

	const MAX_EVENTS       = 200;
	const MAX_EVENT_LENGTH = 4000;

	/**
	 * Genera un reporte HTML amigable y apto para imprimir como PDF.
	 *
	 * @param string $job_id       Trabajo HUNTER AI.
	 * @param array  $events       Línea de tiempo visible de la consola.
	 * @param bool   $include_diff Incluir apéndice técnico con diff.
	 * @return array
	 */
	public static function report( $job_id, $events, $include_diff = true ) {
		$snapshot = ABH_Thoth_AI::report_snapshot( $job_id );
		if ( empty( $snapshot['ok'] ) ) {
			return $snapshot;
		}

		$events   = self::sanitize_events( $events );
		$proposal = array();
		if ( ! empty( $snapshot['pending_token'] ) ) {
			$proposal = ABH_Engine::pending_for_export( $snapshot['pending_token'] );
			if ( empty( $proposal['ok'] ) ) {
				$proposal = array();
			}
		}

		// El reporte es un artefacto compartible. Redacta nuevamente secretos y
		// PII aunque el contexto enviado al modelo ya hubiera sido saneado.
		$privacy  = ABH_Privacy::state();
		$snapshot = self::redact_value( $snapshot, $privacy );
		$proposal = self::redact_value( $proposal, $privacy );
		$events   = self::redact_value( $events, $privacy );

		$html = self::render_report( $snapshot, $proposal, $events, (bool) $include_diff );
		return array(
			'ok'       => true,
			'filename' => sanitize_file_name( $job_id . '-report.html' ),
			'mime'     => 'text/html;charset=utf-8',
			'base64'   => base64_encode( $html ),
		);
	}

	/**
	 * Expediente completo de una operación del Historial, en un solo ZIP.
	 *
	 * Reúne reporte, registro de la consola, diff y manifiesto para que nada se
	 * pierda por descargar los archivos uno a uno.
	 *
	 * @param string $op_id Identificador de operación o transacción.
	 * @return array
	 */
	public static function history_bundle( $op_id ) {
		$op_id = sanitize_text_field( (string) $op_id );
		if ( '' === $op_id ) {
			return array( 'ok' => false, 'message' => __( 'The operation reference is missing.', 'ai-bug-hunter' ) );
		}

		$journal = ABH_Backup::journal();
		$ops     = array();
		foreach ( $journal as $op ) {
			$is_op  = isset( $op['op_id'] ) && hash_equals( (string) $op['op_id'], $op_id );
			$is_txn = isset( $op['txn_id'] ) && '' !== (string) $op['txn_id'] && hash_equals( (string) $op['txn_id'], $op_id );
			if ( $is_op || $is_txn ) {
				$ops[] = $op;
			}
		}
		if ( empty( $ops ) ) {
			return array( 'ok' => false, 'message' => __( 'I did not find that operation in the history.', 'ai-bug-hunter' ) );
		}

		$privacy = ABH_Privacy::state();
		$primary = $ops[0];
		$files   = array();

		$registro = '';
		foreach ( $ops as $op ) {
			if ( ! empty( $op['console_log'] ) ) {
				$registro = (string) $op['console_log'];
				break;
			}
		}
		if ( '' !== $registro ) {
			$files['registro.txt'] = ABH_Privacy::redact( $registro, $privacy );
		}

		$manifest = array(
			'schema'       => 'thoth-ai-history-bundle/1',
			'op_id'        => isset( $primary['op_id'] ) ? $primary['op_id'] : '',
			'txn_id'       => isset( $primary['txn_id'] ) ? $primary['txn_id'] : '',
			'job_id'       => isset( $primary['job_id'] ) ? $primary['job_id'] : '',
			'fecha'        => isset( $primary['ts'] ) ? $primary['ts'] : '',
			'estado'       => isset( $primary['status'] ) ? $primary['status'] : '',
			'modelo'       => ABH_Privacy::mask_if_secret( isset( $primary['model'] ) ? (string) $primary['model'] : '' ),
			'incidencia'   => isset( $primary['incident'] ) ? $primary['incident'] : '',
			'archivos'     => array(),
			'generated_at' => gmdate( 'c' ),
		);
		foreach ( $ops as $op ) {
			$manifest['archivos'][] = array(
				'rel_path'   => isset( $op['rel_path'] ) ? $op['rel_path'] : '',
				'sha_before' => isset( $op['sha_before'] ) ? $op['sha_before'] : '',
				'sha_after'  => isset( $op['sha_after'] ) ? $op['sha_after'] : '',
				'status'     => isset( $op['status'] ) ? $op['status'] : '',
			);
		}
		$files['manifest.json'] = wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );

		// Diff reconstruido comparando el respaldo cifrado con el archivo actual.
		foreach ( $ops as $op ) {
			$rel = isset( $op['rel_path'] ) ? ABH_Guard::normalize( $op['rel_path'] ) : '';
			if ( '' === $rel || empty( $op['backup_file'] ) ) {
				continue;
			}
			$backup = ABH_Backup::locate_backup( $op['backup_file'] );
			if ( ! $backup ) {
				continue;
			}
			$original = ABH_Backup::read_backup( $backup );
			if ( false === $original ) {
				continue;
			}
			$actual = ABH_Engine::read_file( $rel );
			if ( false === $actual ) {
				continue;
			}
			$rows           = ABH_Engine::diff_rows( $original, $actual );
			$name           = 'diff/' . preg_replace( '/[^A-Za-z0-9._-]/', '_', $rel ) . '.diff';
			$files[ $name ] = ABH_Privacy::redact( self::diff_text( $rel, isset( $op['sha_before'] ) ? $op['sha_before'] : '', $rows ), $privacy );
		}

		$files['report.html'] = self::render_history_report( $ops, $privacy );

		$filename = sanitize_file_name( 'HUNTER-' . $op_id . '-case-file.zip' );
		$tmp      = function_exists( 'wp_tempnam' ) ? wp_tempnam( $filename ) : tempnam( function_exists( 'get_temp_dir' ) ? get_temp_dir() : sys_get_temp_dir(), 'thoth-' );
		if ( ! $tmp ) {
			return array( 'ok' => false, 'message' => __( 'I could not create the temporary file for the case file.', 'ai-bug-hunter' ) );
		}
		@chmod( $tmp, 0600 );
		$created = self::create_zip( $tmp, $files );
		if ( ! $created || ! is_readable( $tmp ) ) {
			@unlink( $tmp );
			return array( 'ok' => false, 'message' => __( 'The server could not build the case file ZIP.', 'ai-bug-hunter' ) );
		}
		$bytes = (string) @file_get_contents( $tmp );
		@unlink( $tmp );
		if ( '' === $bytes ) {
			return array( 'ok' => false, 'message' => __( 'The case file ended up empty and was discarded.', 'ai-bug-hunter' ) );
		}

		return array(
			'ok'       => true,
			'filename' => $filename,
			'mime'     => 'application/zip',
			'base64'   => base64_encode( $bytes ),
		);
	}

	/**
	 * Reporte HTML de una operación archivada en el Historial.
	 *
	 * @param array $ops     Operaciones de la transacción.
	 * @param array $privacy Estado de redacción.
	 * @return string
	 */
	private static function render_history_report( $ops, $privacy ) {
		$primary = $ops[0];
		$esc     = static function ( $v ) use ( $privacy ) {
			return esc_html( ABH_Privacy::redact( (string) $v, $privacy ) );
		};

		$html  = '<!doctype html><html lang="en"><head><meta charset="utf-8">';
		$html .= '<meta name="viewport" content="width=device-width,initial-scale=1">';
		$html .= '<title>HUNTER AI · case file</title>';
		$html .= '<style>body{margin:0;background:#f4f6f9;color:#172033;font:15px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}';
		$html .= '.wrap{max-width:900px;margin:0 auto;padding:38px 22px 70px}.hero{background:#111827;color:#fff;border-radius:16px;padding:26px 30px}';
		$html .= '.card{background:#fff;border:1px solid #dbe2ea;border-radius:14px;padding:20px 22px;margin:16px 0}';
		$html .= '.card h2{font-size:18px;margin:0 0 10px}table{width:100%;border-collapse:collapse;font-size:14px}';
		$html .= 'td,th{border:1px solid #dbe2ea;padding:7px 9px;text-align:left}th{background:#f8fafc}';
		$html .= 'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;color:#dce7f5;border-radius:10px;padding:16px;font-size:12px}';
		$html .= 'code{background:#eef2f7;padding:2px 5px;border-radius:4px;font-family:ui-monospace,Consolas,monospace}</style></head><body><main class="wrap">';

		$html .= '<header class="hero"><div style="font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8bc4ff">HUNTER AI · repair record</div>';
		$html .= '<h1 style="margin:8px 0;font-size:26px">' . $esc( isset( $primary['incident'] ) ? $primary['incident'] : __( 'Operation logged', 'ai-bug-hunter' ) ) . '</h1>';
		$html .= '<p style="color:#cbd5e1;margin:0">' . $esc( isset( $primary['ts'] ) ? $primary['ts'] : '' ) . '</p></header>';

		$html .= '<section class="card"><h2>' . esc_html__( 'Operation details', 'ai-bug-hunter' ) . '</h2><table>';
		$html .= '<tr><th>' . esc_html__( 'Reference', 'ai-bug-hunter' ) . '</th><td><code>' . $esc( ! empty( $primary['txn_id'] ) ? $primary['txn_id'] : $primary['op_id'] ) . '</code></td></tr>';
		$html .= '<tr><th>' . esc_html__( 'Status', 'ai-bug-hunter' ) . '</th><td>' . $esc( isset( $primary['status'] ) ? $primary['status'] : '' ) . '</td></tr>';
		$html .= '<tr><th>' . esc_html__( 'Engine', 'ai-bug-hunter' ) . '</th><td>' . $esc( ABH_Privacy::mask_if_secret( isset( $primary['model'] ) ? (string) $primary['model'] : '' ) ) . '</td></tr>';
		$html .= '<tr><th>' . esc_html__( 'Diagnosis', 'ai-bug-hunter' ) . '</th><td>' . $esc( isset( $primary['diagnosis'] ) ? $primary['diagnosis'] : '' ) . '</td></tr>';
		$html .= '</table></section>';

		$html .= '<section class="card"><h2>' . esc_html__( 'Modified files', 'ai-bug-hunter' ) . '</h2><table>';
		$html .= '<tr><th>' . esc_html__( 'File', 'ai-bug-hunter' ) . '</th><th>' . esc_html__( 'Before', 'ai-bug-hunter' ) . '</th><th>' . esc_html__( 'After', 'ai-bug-hunter' ) . '</th></tr>';
		foreach ( $ops as $op ) {
			$html .= '<tr><td><code>' . $esc( isset( $op['rel_path'] ) ? $op['rel_path'] : '' ) . '</code></td>';
			$html .= '<td><code>' . $esc( substr( (string) ( isset( $op['sha_before'] ) ? $op['sha_before'] : '' ), 0, 16 ) ) . '</code></td>';
			$html .= '<td><code>' . $esc( substr( (string) ( isset( $op['sha_after'] ) ? $op['sha_after'] : '' ), 0, 16 ) ) . '</code></td></tr>';
		}
		$html .= '</table></section>';

		$explic = isset( $primary['explicacion'] ) && is_array( $primary['explicacion'] ) ? $primary['explicacion'] : array();
		if ( ! empty( $explic ) ) {
			$campos = array(
				'que_pasa'     => __( 'What was happening', 'ai-bug-hunter' ),
				'causa_raiz'   => __( 'Underlying cause', 'ai-bug-hunter' ),
				'que_hace'     => __( 'What the change did', 'ai-bug-hunter' ),
				'que_no'       => __( 'What it does not solve', 'ai-bug-hunter' ),
				'riesgos'      => __( 'Risks', 'ai-bug-hunter' ),
				'verificacion' => __( 'How to check it', 'ai-bug-hunter' ),
			);
			$html  .= '<section class="card"><h2>' . esc_html__( 'Explanation', 'ai-bug-hunter' ) . '</h2>';
			foreach ( $campos as $k => $label ) {
				if ( ! empty( $explic[ $k ] ) ) {
					$html .= '<h3 style="font-size:14px;color:#46546a;margin:14px 0 4px">' . esc_html( $label ) . '</h3><p>' . $esc( $explic[ $k ] ) . '</p>';
				}
			}
			$html .= '</section>';
		}

		$registro = '';
		foreach ( $ops as $op ) {
			if ( ! empty( $op['console_log'] ) ) {
				$registro = (string) $op['console_log'];
				break;
			}
		}
		$html .= '<section class="card"><h2>' . esc_html__( 'Console log', 'ai-bug-hunter' ) . '</h2>';
		$html .= '' !== $registro
			? '<pre>' . $esc( $registro ) . '</pre>'
			: '<p>' . esc_html__( 'This operation was logged before the console logs were archived.', 'ai-bug-hunter' ) . '</p>';
		$html .= '</section>';

		$html .= '</main></body></html>';
		return $html;
	}

	/**
	 * Construye ZIP con ZipArchive o PclZip.
	 *
	 * @param string $path  Ruta temporal.
	 * @param array  $files Nombre => contenido.
	 * @return bool
	 */
	private static function create_zip( $path, $files ) {
		if ( class_exists( 'ZipArchive' ) ) {
			$zip = new ZipArchive();
			if ( true !== $zip->open( $path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
				return false;
			}
			foreach ( $files as $name => $content ) {
				if ( ! $zip->addFromString( $name, (string) $content ) ) {
					$zip->close();
					return false;
				}
			}
			return $zip->close();
		}

		// Fallback interno sin compresión. Evita depender de extensiones del
		// hosting y es suficiente para microparches pequeños (máximo 5 MiB).
		$body    = '';
		$central = '';
		$offset  = 0;
		$count   = 0;
		foreach ( $files as $name => $content ) {
			$name = str_replace( '\\', '/', ltrim( (string) $name, '/' ) );
			if ( '' === $name || false !== strpos( $name, '../' ) || 0 === strpos( $name, '..' ) ) {
				return false;
			}
			$data = (string) $content;
			$size = strlen( $data );
			$crc  = hexdec( hash( 'crc32b', $data ) );
			$local = pack( 'VvvvvvVVVvv', 0x04034b50, 20, 0, 0, 0, 0, $crc, $size, $size, strlen( $name ), 0 ) . $name . $data;
			$body .= $local;
			$central .= pack( 'VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, 0, 0, 0, 0, $crc, $size, $size, strlen( $name ), 0, 0, 0, 0, 0, $offset ) . $name;
			$offset += strlen( $local );
			$count++;
		}
		$end = pack( 'VvvvvVVv', 0x06054b50, 0, 0, $count, $count, strlen( $central ), strlen( $body ), 0 );
		return false !== @file_put_contents( $path, $body . $central . $end, LOCK_EX );
	}


	/**
	 * Redacta de forma recursiva los textos que saldrán en un reporte.
	 *
	 * @param mixed $value   Valor.
	 * @param array $privacy Estado de redacción por referencia.
	 * @return mixed
	 */
	private static function redact_value( $value, &$privacy ) {
		if ( is_string( $value ) ) {
			$redacted = ABH_Privacy::redact( $value, $privacy );
			return (string) preg_replace( '/ABH_REDACTED_[A-Z0-9]+_(\d+)__/', '[DATO PROTEGIDO $1]', $redacted );
		}
		if ( ! is_array( $value ) ) {
			return $value;
		}
		$out = array();
		foreach ( $value as $key => $item ) {
			$out[ $key ] = self::redact_value( $item, $privacy );
		}
		return $out;
	}

	/**
	 * Limpia la línea de tiempo recibida desde la interfaz.
	 *
	 * @param array $events Eventos.
	 * @return array
	 */
	private static function sanitize_events( $events ) {
		$out = array();
		foreach ( array_slice( is_array( $events ) ? $events : array(), 0, self::MAX_EVENTS ) as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}
			$out[] = array(
				'time'   => substr( sanitize_text_field( isset( $event['time'] ) ? $event['time'] : '' ), 0, 12 ),
				'type'   => substr( sanitize_key( isset( $event['type'] ) ? $event['type'] : 'info' ), 0, 20 ),
				'title'  => substr( sanitize_text_field( isset( $event['title'] ) ? $event['title'] : '' ), 0, 400 ),
				'detail' => substr( sanitize_textarea_field( isset( $event['detail'] ) ? $event['detail'] : '' ), 0, self::MAX_EVENT_LENGTH ),
				'code'   => substr( sanitize_textarea_field( isset( $event['code'] ) ? $event['code'] : '' ), 0, self::MAX_EVENT_LENGTH ),
			);
		}
		return $out;
	}

	/**
	 * Renderiza el documento autocontenido.
	 *
	 * @param array $s            Snapshot.
	 * @param array $proposal     Propuesta.
	 * @param array $events       Eventos.
	 * @param bool  $include_diff Incluir diff.
	 * @return string
	 */
	private static function render_report( $s, $proposal, $events, $include_diff ) {
		$incident  = isset( $s['incident'] ) ? $s['incident'] : array();
		$analysis  = isset( $s['analysis'] ) ? $s['analysis'] : array();
		$challenge = isset( $s['challenge'] ) ? $s['challenge'] : array();
		$evidence  = isset( $s['evidence'] ) ? $s['evidence'] : array();
		$verdict   = isset( $s['verdict'] ) ? $s['verdict'] : array();
		$failure   = isset( $s['failure'] ) ? $s['failure'] : array();
		$contract_failure = isset( $s['contract_failure'] ) ? $s['contract_failure'] : array();
		$recoveries = isset( $s['contract_recoveries'] ) ? $s['contract_recoveries'] : array();
		// Misma fuente que la consola y que el historial: el libro mayor. Si el
		// trabajo es antiguo y no figura en él, se usa lo que el trabajo trae.
		$medidor = ! empty( $s['incident_key'] ) ? ABH_Meter::snapshot( $s['incident_key'] ) : null;
		if ( $medidor && 0 === $medidor['total'] && 0 === $medidor['avoided_total'] ) {
			$medidor = null;
		}
		$usage = ( $medidor && $medidor['total'] > 0 )
			? $medidor['usage']
			: ( isset( $s['usage'] ) && is_array( $s['usage'] ) ? $s['usage'] : array() );
		$state     = isset( $s['state'] ) ? $s['state'] : '';
		$status    = self::status_label( $state );
		$result    = isset( $s['result'] ) && is_array( $s['result'] ) ? $s['result'] : array();
		$verification = isset( $s['verification'] ) && is_array( $s['verification'] ) ? $s['verification'] : array();
		$css = 'body{margin:0;background:#f4f6f9;color:#172033;font:15px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}.wrap{max-width:960px;margin:0 auto;padding:42px 22px 80px}.hero{background:#111827;color:#fff;border-radius:18px;padding:30px 34px;box-shadow:0 18px 45px #11182722}.eyebrow{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8bc4ff}.hero h1{margin:8px 0;font-size:32px}.hero p{color:#cbd5e1}.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.tag{border:1px solid #ffffff2b;border-radius:999px;padding:5px 10px;font-size:12px}.card{background:#fff;border:1px solid #dbe2ea;border-radius:14px;padding:22px 24px;margin:18px 0;box-shadow:0 5px 20px #1720330b}.card h2{font-size:20px;margin:0 0 12px}.card h3{font-size:14px;margin:18px 0 5px;color:#46546a}.call{border-left:4px solid #2563eb;background:#eff6ff;padding:13px 15px;border-radius:0 10px 10px 0}.warn{border-left-color:#d97706;background:#fff7ed}.stop{border-left-color:#dc2626;background:#fef2f2}.ok{border-left-color:#16a34a;background:#f0fdf4}ul{padding-left:20px}li{margin:5px 0}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}code{background:#eef2f7;padding:2px 5px;border-radius:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;color:#dce7f5;border-radius:12px;padding:18px;font-size:12px}.timeline{border-left:2px solid #dbe2ea;margin-left:7px;padding-left:20px}.event{position:relative;margin:0 0 17px}.event:before{content:"";position:absolute;left:-27px;top:7px;width:10px;height:10px;background:#2563eb;border-radius:50%;box-shadow:0 0 0 4px #fff}.event small{color:#64748b}.footer{color:#64748b;font-size:12px;margin-top:28px}details.technical{border:1px solid #dbe2ea;border-radius:10px;padding:12px 14px;margin:14px 0;background:#f8fafc}details.technical>summary{cursor:pointer;font-weight:700;color:#334155}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.metric{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px}.metric strong{display:block;font-size:20px}.runtime-contradiction{border-left:4px solid #dc2626;background:#fef2f2;padding:13px 15px;border-radius:0 10px 10px 0}@media print{body{background:#fff}.wrap{max-width:none;padding:0}.hero,.card{box-shadow:none;break-inside:avoid}.no-print{display:none}}';

		$out  = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . esc_html( $s['job_id'] ) . ' · HUNTER AI</title><style>' . $css . '</style></head><body><main class="wrap">';
		$out .= '<header class="hero"><div class="eyebrow">HUNTER AI · analysis and repair report</div><h1>' . esc_html( isset( $incident['short'] ) ? $incident['short'] : 'Technical review' ) . '</h1><p>This document clearly explains what HUNTER AI observed, which doubts it found, what it decided, and which options remain available.</p><div class="meta"><span class="tag">' . esc_html( $status ) . '</span><span class="tag">Job ' . esc_html( $s['job_id'] ) . '</span><span class="tag">' . esc_html( isset( $incident['rel_path'] ) ? $incident['rel_path'] : '' ) . '</span></div></header>';

		$out .= '<section class="card"><h2>Decision summary</h2>';
		if ( 'verified' === $state ) {
			$out .= '<div class="call ok"><strong>REPAIR COMPLETED AND VERIFIED</strong><br>' . esc_html( ! empty( $verification['verdict'] ) ? __( 'The original detector confirmed that the finding is resolved.', 'ai-bug-hunter' ) : __( 'The finding was closed after post-change verification.', 'ai-bug-hunter' ) ) . '</div>';
			if ( ! empty( $verdict['reason'] ) ) {
				$out .= '<div class="call warn"><strong>Antecedente del Referee</strong><br>' . esc_html( $verdict['reason'] ) . '</div>';
			}
		} elseif ( ! empty( $verdict['reason'] ) ) {
			$out .= '<div class="call ' . ( ! empty( $verdict['repair_allowed'] ) ? 'ok' : 'warn' ) . '"><strong>' . esc_html( self::verdict_label( isset( $verdict['verdict'] ) ? $verdict['verdict'] : '' ) ) . '</strong><br>' . esc_html( $verdict['reason'] ) . '</div>';
		} else {
			$out .= '<p>The review does not yet have a final verdict.</p>';
		}
		if ( ! empty( $failure['message'] ) ) {
			$out .= '<div class="call stop"><strong>The proposal was blocked</strong><br>' . esc_html( $failure['message'] ) . '</div>';
		}
		if ( ! empty( $contract_failure ) ) {
			$out .= '<div class="call stop"><strong>A model phase returned an invalid contract</strong><br>The evidence already collected was preserved. Only the <code>' . esc_html( isset( $contract_failure['phase'] ) ? $contract_failure['phase'] : '' ) . '</code> phase can be retried without repeating the earlier scan.</div>';
			if ( ! empty( $contract_failure['issues'] ) && is_array( $contract_failure['issues'] ) ) {
				$out .= '<h3>Which part of the contract was invalid</h3>' . self::html_list( array_slice( $contract_failure['issues'], 0, 8 ) );
			}
		}
		$out .= '<h3>What you can do now</h3>' . self::next_steps( $s, $proposal ) . '</section>';

		if ( $analysis ) {
			$out .= '<section class="card"><h2>What appears to be happening</h2><p>' . esc_html( $analysis['what_happens'] ) . '</p><h3>Likely cause</h3><p>' . esc_html( $analysis['root_cause'] ) . '</p><h3>What must be preserved</h3><p>' . esc_html( $analysis['behavior_to_preserve'] ) . '</p><h3>Observed evidence</h3>' . self::html_list( $analysis['evidence'] ) . '</section>';
		}
		if ( $challenge ) {
			$out .= '<section class="card"><h2>Questions raised by the Skeptic</h2>' . self::html_list( $challenge['challenges'] ) . '<h3>Alternative explanation</h3><p>' . esc_html( $challenge['alternative_explanation'] ) . '</p><h3>Evidence still missing</h3>' . self::html_list( $challenge['missing_evidence'] ) . '</section>';
		}
		if ( $evidence ) {
			$runtime = isset( $evidence['runtime'] ) && is_array( $evidence['runtime'] ) ? $evidence['runtime'] : array();
			$out .= '<section class="card"><h2>Verified evidence</h2>' . self::html_list( isset( $evidence['summary'] ) ? $evidence['summary'] : array() );
			if ( ! empty( $runtime['summary'] ) ) {
				$out .= '<h3>What PHP observed at runtime</h3>' . self::html_list( $runtime['summary'] );
			}
			$contradictions = array();
			foreach ( isset( $runtime['comparisons'] ) ? (array) $runtime['comparisons'] : array() as $comparison ) {
				if ( is_array( $comparison ) && ! empty( $comparison['contradiction'] ) ) { $contradictions[] = $comparison; }
			}
			if ( $contradictions ) {
				$out .= '<div class="runtime-contradiction"><strong>The loaded code does not match the code on disk.</strong><br>Before editing files, review OPcache, partial deployments, and load paths.</div>';
			}
			$out .= '<p><strong>Files reviewed:</strong> ' . (int) ( isset( $evidence['files_scanned'] ) ? $evidence['files_scanned'] : 0 ) . ( ! empty( $evidence['project_version'] ) ? ' · <strong>Version:</strong> ' . esc_html( $evidence['project_version'] ) : '' ) . '</p>';
			$out .= '<details class="technical"><summary>Technical appendix: symbols, calls, and runtime</summary>';
			$out .= '<h3>Disk ↔ runtime comparison</h3>' . self::runtime_comparisons( isset( $runtime['comparisons'] ) ? $runtime['comparisons'] : array() );
			$out .= '<h3>Methods observed at runtime</h3>' . self::evidence_items( isset( $runtime['methods'] ) ? $runtime['methods'] : array() );
			$out .= '<h3>Related definitions</h3>' . self::evidence_items( isset( $evidence['definitions'] ) ? $evidence['definitions'] : array() );
			$out .= '<h3>Related calls</h3>' . self::evidence_items( isset( $evidence['calls'] ) ? $evidence['calls'] : array() );
			$out .= self::opcache_html( isset( $runtime['opcache'] ) ? $runtime['opcache'] : array() );
			$out .= '</details></section>';
		}
		if ( $verdict ) {
			$out .= '<section class="card"><h2>Requirements and verification</h2><h3>Repair requirements</h3>' . self::html_list( $verdict['requirements'] ) . '<h3>How to verify it</h3>' . self::html_list( $verdict['verification'] ) . '</section>';
		}
		if ( $proposal ) {
			$out .= '<section class="card"><h2>Repair proposal</h2><div class="call ' . ( 'assisted' === $proposal['review_mode'] ? 'warn' : 'ok' ) . '"><strong>' . ( 'assisted' === $proposal['review_mode'] ? 'Candidate under supervision' : 'Diff authorized by the Referee' ) . '</strong><br>' . esc_html( isset( $proposal['diagnosis'] ) ? $proposal['diagnosis'] : '' ) . '</div>';
			if ( ! empty( $proposal['explicacion'] ) ) {
				$out .= '<h3>What it will do</h3><p>' . esc_html( isset( $proposal['explicacion']['que_hace'] ) ? $proposal['explicacion']['que_hace'] : '' ) . '</p><h3>What it does not solve</h3><p>' . esc_html( isset( $proposal['explicacion']['que_no'] ) ? $proposal['explicacion']['que_no'] : '' ) . '</p>';
			}
			if ( $include_diff ) {
				$out .= '<h3>Technical appendix: diff</h3><pre>' . esc_html( self::diff_text( $proposal['rel_path'], $proposal['sha_before'], ABH_Engine::diff_rows( $proposal['original'], $proposal['patched'] ) ) ) . '</pre>';
			}
			$out .= '</section>';
		}

		$out .= '<section class="card"><h2>Review usage</h2><div class="metrics"><div class="metric"><strong>' . (int) ( isset( $usage['in'] ) ? $usage['in'] : 0 ) . '</strong>input tokens</div><div class="metric"><strong>' . (int) ( isset( $usage['out'] ) ? $usage['out'] : 0 ) . '</strong>output tokens</div><div class="metric"><strong>' . esc_html( ABH_Router::cost_label( $usage ) ? ABH_Router::cost_label( $usage ) : 'Not configured' ) . '</strong>estimated cost</div></div>';
		if ( $medidor ) {
			$out .= '<p>' . esc_html( $medidor['label'] );
			if ( $medidor['avoided_total'] ) {
				$out .= ' ' . esc_html(
					sprintf(
						/* translators: %s: tokens ahorrados. */
						__( 'Saved by deterministic repair: about %s tokens.', 'ai-bug-hunter' ),
						number_format_i18n( $medidor['avoided_total'] )
					)
				);
			}
			$out .= '</p>';
		}
		if ( $recoveries ) { $out .= '<p>Contracts recovered automatically: <strong>' . count( $recoveries ) . '</strong>.</p>'; }
		$out .= '</section>';

		$out .= '<section class="card"><details class="technical"><summary>Complete technical log</summary><div class="timeline">';
		// Las preguntas escritas en la terminal forman parte de la misma
		// transcripción, así que salen en el reporte con su etiqueta y no como
		// un críptico «YOU».
		$etiquetas = array(
			'you'   => __( 'YOU', 'ai-bug-hunter' ),
			'ai'    => 'HUNTER AI',
			'ok'    => __( 'DONE', 'ai-bug-hunter' ),
			'work'  => __( 'IN PROGRESS', 'ai-bug-hunter' ),
			'warn'  => __( 'ATTENTION', 'ai-bug-hunter' ),
			'error' => __( 'HIGH', 'ai-bug-hunter' ),
		);
		foreach ( $events as $event ) {
			$etiqueta = isset( $etiquetas[ $event['type'] ] ) ? $etiquetas[ $event['type'] ] : strtoupper( $event['type'] );
			$out .= '<div class="event event-' . esc_attr( $event['type'] ) . '"><small>' . esc_html( $event['time'] . ' · ' . $etiqueta ) . '</small><strong>' . esc_html( $event['title'] ) . '</strong>';
			if ( '' !== $event['detail'] ) { $out .= '<p>' . nl2br( esc_html( $event['detail'] ) ) . '</p>'; }
			if ( '' !== $event['code'] ) { $out .= '<pre>' . esc_html( $event['code'] ) . '</pre>'; }
			$out .= '</div>';
		}
		$out .= '</div></details></section>';

		$out .= '<section class="card"><h2>Technical data</h2><p><strong>Original SHA-256:</strong> <code>' . esc_html( isset( $s['sha_before'] ) ? $s['sha_before'] : '' ) . '</code></p>'
			. ( ! empty( $result['sha_after'] ) ? '<p><strong>Post-change SHA-256:</strong> <code>' . esc_html( $result['sha_after'] ) . '</code></p>' : '' )
			. ( ! empty( $result['op_id'] ) ? '<p><strong>Rollback reference:</strong> <code>' . esc_html( $result['op_id'] ) . '</code></p>' : '' )
			. '<p><strong>Internal status:</strong> <code>' . esc_html( $state ) . '</code></p><p><strong>Generated:</strong> ' . esc_html( gmdate( 'Y-m-d H:i:s' ) ) . ' UTC</p></section>';
		$out .= '<p class="footer">This report does not replace a complete backup. A repair is considered complete only when the original test no longer reproduces the issue and legitimate behavior continues to work.</p></main></body></html>';
		return $out;
	}

	private static function html_list( $items ) {
		if ( empty( $items ) || ! is_array( $items ) ) {
			return '<p>No additional items were recorded.</p>';
		}
		$out = '<ul>';
		foreach ( $items as $item ) {
			$out .= '<li>' . esc_html( $item ) . '</li>';
		}
		return $out . '</ul>';
	}


	private static function evidence_items( $items ) {
		if ( empty( $items ) || ! is_array( $items ) ) {
			return '<p>No se encontraron elementos relacionados.</p>';
		}
		$out = '<ul>';
		foreach ( array_slice( $items, 0, 40 ) as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$symbol = ( ! empty( $item['class'] ) ? $item['class'] . '::' : '' ) . ( isset( $item['name'] ) ? $item['name'] : '' );
			$line = ! empty( $item['line'] ) ? (int) $item['line'] : ( ! empty( $item['start_line'] ) ? (int) $item['start_line'] : 0 );
			$location = isset( $item['file'] ) ? $item['file'] . ( $line > 0 ? ':' . $line : '' ) : '';
			$visibility = isset( $item['exists'] ) && ! $item['exists'] ? ' · ausente en runtime' : ( ! empty( $item['visibility'] ) ? ' · ' . $item['visibility'] : '' );
			$out .= '<li><code>' . esc_html( $symbol ) . '</code>' . esc_html( $visibility ) . ( '' !== $location ? '<br><small>' . esc_html( $location ) . '</small>' : '' ) . '</li>';
		}
		return $out . '</ul>';
	}


	private static function runtime_comparisons( $items ) {
		if ( empty( $items ) || ! is_array( $items ) ) {
			return '<p>No comparable symbols were found between disk and runtime.</p>';
		}
		$out = '<ul>';
		foreach ( array_slice( $items, 0, 30 ) as $item ) {
			if ( ! is_array( $item ) ) { continue; }
			$out .= '<li><code>' . esc_html( isset( $item['symbol'] ) ? $item['symbol'] : '' ) . '</code>: disk <strong>' . esc_html( isset( $item['disk_visibility'] ) ? $item['disk_visibility'] : '?' ) . '</strong> · runtime <strong>' . esc_html( isset( $item['runtime_visibility'] ) ? $item['runtime_visibility'] : '?' ) . '</strong>' . ( ! empty( $item['contradiction'] ) ? ' · <strong>contradiction</strong>' : ' · matches' ) . '</li>';
		}
		return $out . '</ul>';
	}

	private static function opcache_html( $opcache ) {
		if ( empty( $opcache ) || ! is_array( $opcache ) ) {
			return '<h3>OPcache</h3><p>No information was available.</p>';
		}
		return '<h3>OPcache</h3><ul><li>Available: ' . ( ! empty( $opcache['available'] ) ? 'yes' : 'no' ) . '</li><li>Enabled: ' . ( ! empty( $opcache['enabled'] ) ? 'yes' : 'no' ) . '</li><li>Timestamp validation: ' . ( ! isset( $opcache['validate_timestamps'] ) ? 'unknown' : ( $opcache['validate_timestamps'] ? 'enabled' : 'disabled' ) ) . '</li><li>Revalidation frequency: ' . ( isset( $opcache['revalidate_freq'] ) ? (int) $opcache['revalidate_freq'] . ' s' : 'unknown' ) . '</li><li>Restricted API: ' . ( ! empty( $opcache['restrict_api_configured'] ) ? 'yes' : 'no' ) . '</li></ul>';
	}

	private static function next_steps( $s, $proposal ) {
		$state = isset( $s['state'] ) ? $s['state'] : '';
		if ( 'verified' === $state ) {
			return '<ul><li>Keep the report and rollback reference.</li><li>Review History if you want to audit or revert the change.</li><li>The finding should no longer appear as pending.</li></ul>';
		}
		if ( 'model_contract_error' === $state ) {
			return '<ul><li>Retry only the phase whose contract failed.</li><li>Keep the evidence, hashes, and earlier phases.</li><li>Download the report if manual review is required.</li></ul>';
		}
		if ( in_array( $state, array( 'fix_rejected', 'assisted_fix_blocked' ), true ) ) {
			return '<ul><li>Collect code evidence again and update the hypothesis.</li><li>Try a smaller structured patch.</li><li>Download this report for manual review. No files were modified.</li></ul>';
		}
		if ( $proposal ) {
			if ( 'assisted' === $proposal['review_mode'] && empty( $proposal['apply_allowed'] ) ) {
				return '<ul><li>Download the diff and review it in staging.</li><li>Collect the missing evidence before applying the change manually.</li><li>Run the original test after the change.</li></ul>';
			}
			return '<ul><li>Review the complete diff.</li><li>Approve it only if the change matches the expected behavior.</li><li>Create a backup and run post-change verification.</li></ul>';
		}
		$verdict = isset( $s['verdict']['verdict'] ) ? $s['verdict']['verdict'] : '';
		if ( 'manual_review' === $verdict ) {
			return '<ul><li>Open the manual repair guide and review the diagnosis.</li><li>Verify the deployed version and the evidence identified by the Referee.</li><li>Make the change outside the plugin, first in staging, and verify the result.</li></ul>';
		}
		return '<ul><li>Keep this report as evidence.</li><li>Collect additional information or run the detector again.</li></ul>';
	}

	private static function status_label( $state ) {
		$labels = array(
			'observed'               => 'Observation started',
			'analyzed'               => 'Analysis available',
			'challenged'             => 'Critical review available',
			'evidence_collected'     => 'Code evidence collected',
			'evidence_analyzed'      => 'Hypothesis updated with evidence',
			'evidence_challenged'    => 'Critical review enriched',
			'model_contract_error'   => 'Invalid model contract; resume available',
			'confirmed'              => 'Finding confirmed',
			'manual_review'          => 'Human review and authorization required',
			'signal_only'            => 'Unconfirmed signal',
			'false_positive'         => __( 'False positive', 'ai-bug-hunter' ),
			'diff_ready'             => 'Diff ready for review',
			'assisted_diff_ready'    => 'Assisted candidate ready',
			'fix_rejected'           => 'Proposal rejected by a safety gate',
			'assisted_fix_blocked'   => 'Assisted candidate blocked',
			'applied_pending_rescan' => 'Change applied · verification pending',
			'partial'                => 'Partial mitigation',
			'verified'               => 'Repair completed and verified',
			'still_failing'          => 'Change applied · the error continues',
		);
		return isset( $labels[ $state ] ) ? $labels[ $state ] : 'Review in progress';
	}

	private static function verdict_label( $verdict ) {
		$labels = array(
			'confirmed'      => 'Finding confirmed',
			'manual_review'  => 'HUMAN REVIEW AND AUTHORIZATION REQUIRED',
			'signal_only'    => 'Unconfirmed signal',
			'false_positive' => __( 'False positive', 'ai-bug-hunter' ),
		);
		return isset( $labels[ $verdict ] ) ? $labels[ $verdict ] : __( 'No verdict', 'ai-bug-hunter' );
	}

	private static function diff_text( $rel, $sha, $rows ) {
		$out = array( '# HUNTER AI', '# File: ' . $rel, '# Original SHA-256: ' . $sha, '--- a/' . $rel, '+++ b/' . $rel );
		foreach ( $rows as $row ) {
			if ( 'gap' === $row['type'] ) {
				$out[] = '@@ … @@';
			} else {
				$out[] = ( 'add' === $row['type'] ? '+' : ( 'del' === $row['type'] ? '-' : ' ' ) ) . $row['text'];
			}
		}
		return implode( "\n", $out ) . "\n";
	}
}
