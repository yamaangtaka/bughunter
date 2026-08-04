<?php
/**
 * Manejadores AJAX. Todos exigen permisos de administrador y nonce válido.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Es la puerta de entrada de TODO lo que el navegador puede pedirle al plugin.
 *
 * POR QUE EXISTE:  Cada manejador exige capacidad de administrador y nonce válido antes de hacer nada. Esa comprobación es lo que separa al dueño de un tercero.
 *
 * SI LO RECORTAS:  Un endpoint nuevo sin guard_request() es un agujero. No hay excepciones ni casos «inofensivos».
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

// phpcs:disable WordPress.Security.NonceVerification.Missing -- Every public handler calls guard_request(), which delegates to ABH_Admin::guard_ajax_request() before reading request data.

/**
 * Class ABH_Ajax
 */
class ABH_Ajax {

	/**
	 * Registra los endpoints.
	 *
	 * @return void
	 */
	public static function init() {
		// `rollback` está en la lista a propósito: deshacer NO aplica nada
		// generado fuera. Reescribe los bytes que este plugin guardó —cifrados y
		// autenticados— antes de tocar el archivo, y por eso no cruza la
		// frontera de edición. `apply` sigue ausente a propósito: ese sí
		// escribiría contenido venido de fuera. No lo añadas; el manejador que
		// queda con ese nombre es un rechazo duro que no escribe nada.
		// `report_send` ya no aparece porque su manejador no existe: se borró
		// junto con el transporte, para que esta edición no pueda mandar
		// reportes a ningún servicio externo ni por descuido.
		$actions = array( 'analyze', 'advise', 'test', 'clear_log', 'purge', 'env_fix', 'dismiss', 'undismiss', 'guard_fix', 'env_preview', 'thoth_start', 'thoth_local_triage', 'thoth_analyze', 'thoth_challenge', 'thoth_collect_evidence', 'thoth_reanalyze', 'thoth_rechallenge', 'thoth_resume_contract', 'thoth_adjudicate', 'thoth_prepare_fix', 'manual_guide', 'export_report', 'export_history', 'purge_resolved', 'thoth_verify', 'thoth_settle', 'thoth_discard', 'chat', 'core_scan_start', 'core_scan_step', 'core_file_diff', 'core_file_restore', 'core_file_accept', 'core_blame', 'cve_refresh', 'watchdog_install', 'watchdog_uninstall', 'watchdog_clear', 'syntax_scan_start', 'syntax_scan_step', 'health_prune', 'report_preview', 'rollback' );
		foreach ( $actions as $a ) {
			add_action( 'wp_ajax_abh_' . $a, array( __CLASS__, 'handle_' . $a ) );
		}
	}

	/**
	 * Arma el modo root para un plan concreto.
	 *
	 * Sólo llega aquí si la persona escribió la frase. No se acepta un armado
	 * «en general»: se firma el plan que se tiene delante, con su huella, y si
	 * el plan cambia después la firma deja de valer.
	 *
	 * @return void
	 */
	public static function handle_root_armar() {
		self::guard_request();

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$frase = isset( $_POST['frase'] ) ? sanitize_text_field( wp_unslash( $_POST['frase'] ) ) : '';
		if ( '' === $token ) {
			wp_send_json_error( array( 'message' => __( 'The change reference is missing.', 'ai-bug-hunter' ) ) );
		}
		// Se firma el plan EXACTO tal como está guardado, no una versión
		// normalizada para pantalla: si la huella no correspondiera a lo que
		// luego se aplica, la firma no estaría autorizando nada.
		$pending = ABH_Engine::pending_raw( $token );
		if ( ! $pending ) {
			wp_send_json_error( array( 'message' => __( 'The proposal expired or belongs to another session. Analyze the error again.', 'ai-bug-hunter' ) ) );
		}
		$res = ABH_Root::armar( $pending, $frase );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success(
			array(
				'armado'  => true,
				'ventana' => ABH_Root::VENTANA,
				'message' => __( 'Root mode armed. It disarms itself when the plan finishes.', 'ai-bug-hunter' ),
			)
		);
	}

	/**
	 * Desarma el modo root.
	 *
	 * @return void
	 */
	public static function handle_root_desarmar() {
		self::guard_request();
		ABH_Root::desarmar();
		wp_send_json_success( array( 'armado' => false ) );
	}

	/**
	 * Exige firma para una acción que toca algo grave fuera del flujo de planes.
	 *
	 * Instalar el testigo escribe un mu-plugin —se carga antes que WordPress
	 * entero— y restaurar un archivo del núcleo escribe en wp-admin o
	 * wp-includes. Las dos son exactamente los motivos que el modo root declara
	 * graves, y las dos entraban por su propia puerta sin firmar nada.
	 *
	 * No cancela: devuelve la petición de firma con la ruta concreta, y quien
	 * la firme repite la acción.
	 *
	 * @param string $rel Ruta relativa que se va a tocar.
	 * @return void
	 */
	// RETIRADA A PROPÓSITO. Construía una carga sintética sin `contenido`, y la
	// huella de ABH_Root incluye el hash del contenido: ningún payload
	// almacenable puede producir esa huella, así que armado_para() nunca
	// devolvía true. Sumado a que armar exige un token de propuesta pendiente
	// —y una acción directa no crea propuesta—, la firma que pedía era
	// imposible de dar y las dos acciones que la usaban quedaban muertas.
	// No la reintroduzcas sin construir antes un camino de armado para acciones
	// sin propuesta. Y antes de construirlo, lee por qué se decidió que no hace
	// falta: la frase protege del código que un modelo escribió y el dueño no
	// leyó, no de un botón que el dueño pulsa sabiendo qué hace.

	/**
	 * Comprobación de permisos común.
	 *
	 * @return void
	 */
	/**
	 * Responde una acción de HUNTER sellando el medidor de la incidencia.
	 *
	 * El navegador no acumula tokens por su cuenta: lo que pinta la consola es
	 * exactamente lo que dice el libro mayor del servidor, que es también lo
	 * que sale en el reporte y lo que se factura.
	 *
	 * @param array $res Respuesta.
	 * @return void
	 */
	private static function thoth_reply( $res ) {
		$res = ABH_Meter::stamp( $res );
		$res = ABH_Edition::normalize_ai_result( $res );

		// Si la terminal admite escritura lo decide el SERVIDOR, con la misma
		// función que decide si responde. El navegador solo refleja este dato.
		//
		// Antes lo deducía por su cuenta y se equivocaba en las dos
		// direcciones: abría el prompt en flujos cuyo identificador no es un
		// trabajo THOTH —el arreglo del guardián, el escaneo de sintaxis— donde
		// el servidor rechaza siempre, y no lo cerraba nunca al terminar, así
		// que tras verificar una reparación seguía invitando a escribir en un
		// estado en el que ya no se contesta.
		//
		// Va aquí porque es el único punto por el que pasan todas las
		// respuestas del pipeline, con éxito y con fallo.
		if ( class_exists( 'ABH_Chat' ) ) {
			$trabajo = '';
			if ( ! empty( $res['job_id'] ) ) {
				$trabajo = (string) $res['job_id'];
			} elseif ( isset( $_POST['job'] ) ) {
				$trabajo = sanitize_text_field( wp_unslash( $_POST['job'] ) );
			}
			$res['chat_open'] = (bool) ( ABH_Chat::allowed() && ABH_Chat::open_for( $trabajo ) );
		}

		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Permiso y nonce obligatorios.
	 *
	 * La comprobación vive entera en ABH_Admin::guard_ajax_request(): aquí solo
	 * se delega. Si necesitas endurecer el portero, hazlo allí, no aquí.
	 *
	 * @return void
	 */
	private static function guard_request() {
		ABH_Admin::guard_ajax_request();
	}



	/**
	 * Inicia el escaneo sintáctico por bloques.
	 *
	 * @return void
	 */
	public static function handle_syntax_scan_start() {
		self::guard_request();
		$scope = isset( $_POST['scope'] ) ? sanitize_key( wp_unslash( $_POST['scope'] ) ) : 'quick';
		$res   = ABH_Scanner::start( $scope );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Procesa un bloque del escaneo sintáctico.
	 *
	 * @return void
	 */
	public static function handle_syntax_scan_step() {
		self::guard_request();
		$scan_id = isset( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : '';
		if ( '' === $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'The scan reference is missing.', 'ai-bug-hunter' ) ) );
		}
		$res = ABH_Scanner::step( $scan_id );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Inicia una sesión de HUNTER AI y congela el hash del archivo.
	 *
	 * @return void
	 */
	public static function handle_thoth_start() {
		self::guard_request();
		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$res = ABH_Thoth_AI::start( $key );
		self::thoth_reply( $res );
	}

	/**
	 * Prueba los motores deterministas antes de llamar al proveedor.
	 *
	 * @return void
	 */
	public static function handle_thoth_local_triage() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::local_triage( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Ejecuta la fase Analyst.
	 *
	 * @return void
	 */
	public static function handle_thoth_analyze() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::analyze( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Ejecuta la fase Skeptic.
	 *
	 * @return void
	 */
	public static function handle_thoth_challenge() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::challenge( $job );
		self::thoth_reply( $res );
	}


	/**
	 * Recopila evidencia determinista del código desplegado.
	 *
	 * @return void
	 */
	public static function handle_thoth_collect_evidence() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::collect_evidence( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Actualiza la hipótesis con la evidencia recopilada.
	 *
	 * @return void
	 */
	public static function handle_thoth_reanalyze() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::reanalyze( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Repite la revisión crítica con la evidencia recopilada.
	 *
	 * @return void
	 */
	public static function handle_thoth_rechallenge() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::rechallenge( $job );
		self::thoth_reply( $res );
	}


	/**
	 * Reanuda exclusivamente una fase cuyo contrato de modelo falló.
	 *
	 * @return void
	 */
	public static function handle_thoth_resume_contract() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::resume_contract( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Ejecuta la fase Referee.
	 *
	 * @return void
	 */
	public static function handle_thoth_adjudicate() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::adjudicate( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Prepara el diff después del veredicto.
	 *
	 * @return void
	 */
	public static function handle_thoth_prepare_fix() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::prepare_fix( $job );
		self::thoth_reply( $res );
	}


	/**
	 * Prepara un candidato de reparación bajo revisión manual.
	 *
	 * @return void
	 */
	public static function handle_manual_guide() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$res = ABH_Thoth_AI::manual_guide( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Exporta un reporte HTML autocontenido.
	 *
	 * @return void
	 */
	/**
	 * Arma el reporte anónimo y lo devuelve para que se vea ANTES de enviarlo.
	 *
	 * No manda nada. La misma regla que rige el resto del plugin: primero se
	 * enseña, después se decide.
	 *
	 * @return void
	 */
	public static function handle_report_preview() {
		self::guard_request();
		$res = self::report_payload();
		wp_send_json_success(
			array(
				'reporte' => $res,
				'json'    => ABH_Report::json( $res ),
				'destino' => '' !== ABH_Report::destino(),
			)
		);
	}


	// RETIRADO A PROPÓSITO: handle_report_send(). Esta edición no manda reportes
	// a ningún servicio externo, y así lo promete el readme. Mientras existiera
	// el manejador, la promesa dependía de que nadie añadiera 'report_send' a la
	// lista de acciones de arriba: una línea de distancia. Borrado el manejador
	// —y con él ABH_Report::send()—, ya no hay nada que registrar. El reporte se
	// sigue armando y se sigue enseñando con `report_preview`, y quien quiera
	// mandarlo lo descarga y lo manda por su cuenta. No lo reintroduzcas.

	/**
	 * Reporte anónimo a partir de la petición actual.
	 *
	 * @return array
	 */
	private static function report_payload() {
		$job_id = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$motivo = isset( $_POST['motivo'] ) ? sanitize_textarea_field( wp_unslash( $_POST['motivo'] ) ) : '';

		$raw = isset( $_POST['events'] ) ? (string) wp_unslash( $_POST['events'] ) : '[]'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Bounded JSON is decoded and each report field is escaped by ABH_Report.
		if ( strlen( $raw ) > 204800 ) {
			wp_send_json_error( array( 'message' => __( 'The visible log is too large. Download the case file and send it yourself.', 'ai-bug-hunter' ) ), 413 );
		}
		$eventos = json_decode( $raw, true );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $eventos ) ) {
			$eventos = array();
		}

		$job = '' !== $job_id ? ABH_Thoth_AI::job( $job_id ) : false;
		return ABH_Report::build( is_array( $job ) ? $job : array(), $eventos, $motivo );
	}


	public static function handle_export_report() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$raw_events = isset( $_POST['events'] ) ? (string) wp_unslash( $_POST['events'] ) : '[]'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Bounded JSON is decoded and normalized by the artifact builder.
		if ( strlen( $raw_events ) > 204800 ) {
			wp_send_json_error(
				array( 'message' => __( 'The visible log is too large to export safely. Download the text log first, or use Show all and try again.', 'ai-bug-hunter' ) ),
				413
			);
		}
		$events = json_decode( $raw_events, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			wp_send_json_error( array( 'message' => __( 'The visible log does not have a valid format and was not included in the report.', 'ai-bug-hunter' ) ), 400 );
		}
		$include_diff = ! isset( $_POST['include_diff'] ) || '0' !== sanitize_key( wp_unslash( $_POST['include_diff'] ) );
		$res = ABH_Artifacts::report( $job, is_array( $events ) ? $events : array(), $include_diff );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Descarga el expediente completo de una operación del Historial en un ZIP
	 * (reporte, registro de la consola, diff y manifiesto), para que nada se
	 * pierda por descargar los archivos uno por uno.
	 *
	 * @return void
	 */
	public static function handle_export_history() {
		self::guard_request();
		$op  = isset( $_POST['op'] ) ? sanitize_text_field( wp_unslash( $_POST['op'] ) ) : '';
		$res = ABH_Artifacts::history_bundle( $op );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Analiza una incidencia y propone un arreglo. No escribe nada.
	 *
	 * @return void
	 */
	public static function handle_analyze() {
		self::guard_request();
		wp_send_json_error(
			array(
				'stage'   => 'legacy_disabled',
				'message' => __( 'The previous direct flow is disabled. Start the repair from HUNTER AI Repair Console to complete Analyst, Skeptic and Referee.', 'ai-bug-hunter' ),
			),
			409
		);
	}

	/**
	 * Aplica un arreglo aprobado por el usuario.
	 *
	 * @return void
	 */
	public static function handle_apply() {
		self::guard_request();
		wp_send_json_error( ABH_Edition::application_refused(), 403 );
	}

	/**
	 * Revierte un cambio.
	 *
	 * @return void
	 */
	/**
	 * Cierra el medidor de una incidencia cuando el usuario no aplica nada.
	 *
	 * Solo acepta desenlaces que abaratan: aplicar es el único que cobra
	 * completo y eso lo decide el servidor al escribir, nunca el navegador.
	 *
	 * @return void
	 */
	public static function handle_thoth_settle() {
		self::guard_request();
		$job     = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$outcome = isset( $_POST['outcome'] ) ? sanitize_key( wp_unslash( $_POST['outcome'] ) ) : '';
		if ( ! in_array( $outcome, array( 'declined', 'failed', 'inconclusive' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Outcome not recognized.', 'ai-bug-hunter' ) ), 400 );
		}
		$key = ABH_Thoth_AI::incident_key_of( $job );
		if ( '' === $key ) {
			wp_send_json_error( array( 'message' => __( 'That session no longer exists.', 'ai-bug-hunter' ) ), 404 );
		}
		if ( 'declined' === $outcome ) {
			ABH_Thoth_AI::forget_active();
		}
		wp_send_json_success( ABH_Meter::settle( $key, $outcome ) );
	}

	/**
	 * Descarta la reparación a medias del usuario, sin tocar el trabajo cifrado.
	 *
	 * @return void
	 */
	public static function handle_thoth_discard() {
		self::guard_request();
		ABH_Thoth_AI::forget_active();
		wp_send_json_success( array( 'message' => __( 'Repair discarded. The record of the issue is still intact.', 'ai-bug-hunter' ) ) );
	}

	public static function handle_rollback() {
		self::guard_request();

		$op    = isset( $_POST['op'] ) ? sanitize_text_field( wp_unslash( $_POST['op'] ) ) : '';
		$force = isset( $_POST['force'] ) && '1' === $_POST['force'];

		$antes = ABH_Backup::get( $op );
		$res   = ABH_Backup::rollback( $op, $force );
		if ( ! $res['ok'] ) {
			wp_send_json_error( $res );
		}
		// Hubo que deshacerlo: ese gasto lo asumimos nosotros, no se cobra.
		if ( is_array( $antes ) && ! empty( $antes['incident_key'] ) ) {
			ABH_Meter::settle( $antes['incident_key'], 'rolled_back' );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Asesoría: explica cómo corregir a mano.
	 *
	 * @return void
	 */
	public static function handle_advise() {
		self::guard_request();

		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$inc = ABH_Scanner::get_incident( $key );
		if ( ! $inc ) {
			wp_send_json_error( array( 'message' => __( 'That issue is no longer available. Reload the diagnosis or run a new scan.', 'ai-bug-hunter' ) ) );
		}

		$pregunta = sprintf(
			'The error log says: %1$s: %2$s (file %3$s, line %4$d). Explain carefully, step by step, how I can fix it myself.',
			$inc['kind'],
			$inc['short'],
			'' !== $inc['rel_path'] ? $inc['rel_path'] : '(desconocido)',
			(int) $inc['line']
		);

		$res = ABH_Engine::advise( $inc['rel_path'], $pregunta );
		if ( ! $res['ok'] ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success(
			array(
				'html'  => wpautop( esc_html( $res['text'] ) ),
				'usage' => isset( $res['usage'] ) ? $res['usage'] : array(),
				'cost'  => isset( $res['cost'] ) ? $res['cost'] : '',
			)
		);
	}


	/**
	 * Vista previa de una corrección de entorno. No modifica nada.
	 *
	 * @return void
	 */
	public static function handle_env_preview() {
		self::guard_request();
		$key  = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$diag = null;

		if ( 'log' === $key ) {
			$blocked = ABH_Logs::unreadable_candidates();
			if ( empty( $blocked ) ) {
				wp_send_json_error( array( 'message' => __( 'The log is already readable.', 'ai-bug-hunter' ) ) );
			}
			$info = ABH_Motor::inspect( $blocked[0] );
			$mode = ABH_Motor::is_sensitive_log( $blocked[0] ) ? ABH_Motor::MODE_PRIVATE_FILE : ABH_Motor::MODE_FILE;
			$diag = ABH_Motor::describe(
				array(
					'code'        => 'ABH-ENV-001',
					'diagnosis'   => __( 'AI Bug Hunter cannot read the log with its current permissions. We can give the PHP process access without deliberately making it public.', 'ai-bug-hunter' ),
					'steps'       => array(
						__( 'Only the file permissions will be changed.', 'ai-bug-hunter' ),
						__( 'Afterwards we will read the log again.', 'ai-bug-hunter' ),
						__( 'This does not replace THOTH Security\'s public exposure check.', 'ai-bug-hunter' ),
					),
					'fixable'     => ABH_Motor::env_fixable( $blocked[0] ),
					'fix'         => array( 'type' => 'chmod', 'path' => $blocked[0], 'mode' => $mode ),
					'target_path' => $blocked[0],
					'inspection'  => $info,
				)
			);
		} else {
			$inc = ABH_Scanner::get_incident( $key );
			if ( ! $inc ) {
				wp_send_json_error( array( 'message' => __( 'The issue is no longer available.', 'ai-bug-hunter' ) ) );
			}
			$diag = ABH_Motor::diagnose( $inc );
		}

		if ( ! is_array( $diag ) || empty( $diag['fixable'] ) || empty( $diag['fix'] ) ) {
			wp_send_json_error( array( 'message' => __( 'This fix requires manual steps and cannot be applied from the console.', 'ai-bug-hunter' ) ) );
		}

		$path      = isset( $diag['fix']['path'] ) ? (string) $diag['fix']['path'] : '';
		$sensitive = ABH_Motor::is_sensitive_log( $path );
		$preview_token = wp_generate_password( 32, false, false );
		$preview_data  = array(
			'user_id' => get_current_user_id(),
			'key'     => $key,
			'path'    => wp_normalize_path( $path ),
			'mode'    => (int) $diag['fix']['mode'],
			'perms'   => isset( $diag['inspection']['perms'] ) ? (string) $diag['inspection']['perms'] : '',
		);
		$sealed = ABH_Crypto::encrypt( wp_json_encode( $preview_data ), 'env-preview' );
		if ( false === $sealed || ! set_transient( 'abh_env_preview_' . $preview_token, $sealed, 600 ) ) {
			wp_send_json_error( array( 'message' => __( 'I could not create an encrypted approval for this permissions change.', 'ai-bug-hunter' ) ) );
		}
		wp_send_json_success(
			array(
				'preview_token'     => $preview_token,
				'code'              => $diag['code'],
				'title'             => $diag['titulo'],
				'diagnosis'         => $diag['diagnosis'],
				'steps'             => $diag['steps'],
				'rel_path'          => ABH_Motor::rel_of( $path ),
				'mode_before'       => isset( $diag['inspection']['perms'] ) ? $diag['inspection']['perms'] : '',
				'mode_after'        => substr( sprintf( '%o', (int) $diag['fix']['mode'] ), -3 ),
				'sensitive_log'     => $sensitive,
				'security_complete' => ! $sensitive,
				'message'           => $sensitive
					? __( 'This change restores technical access to the log, but the public exposure is only considered resolved after THOTH Security rescans it.', 'ai-bug-hunter' )
					: __( 'The fix is ready for your approval.', 'ai-bug-hunter' ),
			)
		);
	}

	/**
	 * Corrige un problema de entorno detectado por el motor (sin IA).
	 * El diagnóstico se vuelve a calcular en el servidor: nunca se confía
	 * en lo que envía el navegador.
	 *
	 * @return void
	 */
	public static function handle_env_fix() {
		self::guard_request();

		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$preview_token = isset( $_POST['preview_token'] ) ? sanitize_text_field( wp_unslash( $_POST['preview_token'] ) ) : '';
		$sealed = '' !== $preview_token ? get_transient( 'abh_env_preview_' . $preview_token ) : false;
		$plain  = ABH_Crypto::is_encrypted( $sealed ) ? ABH_Crypto::decrypt( $sealed, 'env-preview' ) : false;
		$approved = false !== $plain ? json_decode( $plain, true ) : null;
		if ( ! is_array( $approved ) || ! isset( $approved['user_id'], $approved['key'], $approved['path'], $approved['mode'] ) || (int) $approved['user_id'] !== get_current_user_id() || ! hash_equals( (string) $approved['key'], (string) $key ) ) {
			wp_send_json_error( array( 'message' => __( 'A valid preview for this change is missing. Open the console again.', 'ai-bug-hunter' ) ), 409 );
		}
		delete_transient( 'abh_env_preview_' . $preview_token );

		// Caso especial: el propio registro es ilegible, así que no hay incidencia.
		if ( 'log' === $key ) {
			$bloqueados = ABH_Logs::unreadable_candidates();
			if ( empty( $bloqueados ) ) {
				wp_send_json_error( array( 'message' => __( 'The log is already readable.', 'ai-bug-hunter' ) ) );
			}
			$info = ABH_Motor::inspect( $bloqueados[0] );
			$mode = ABH_Motor::is_sensitive_log( $bloqueados[0] ) ? ABH_Motor::MODE_PRIVATE_FILE : ABH_Motor::MODE_FILE;
			if ( ! hash_equals( (string) $approved['path'], wp_normalize_path( $bloqueados[0] ) ) || (int) $approved['mode'] !== $mode ) {
				wp_send_json_error( array( 'message' => __( 'The permission change no longer matches the preview. It was not applied.', 'ai-bug-hunter' ) ), 409 );
			}
			$res  = ABH_Motor::apply_fix(
				array(
					'code'    => 'ABH-ENV-001',
					'fixable' => ABH_Motor::env_fixable( $bloqueados[0] ),
					'fix'     => array(
						'type' => 'chmod',
						'path' => $bloqueados[0],
						'mode' => $mode,
					),
				)
			);
			if ( ! $res['ok'] ) {
				wp_send_json_error( $res );
			}
			wp_send_json_success( $res );
		}

		$inc = ABH_Scanner::get_incident( $key );
		if ( ! $inc ) {
			wp_send_json_error( array( 'message' => __( 'That issue is no longer available. Reload the diagnosis or run a new scan.', 'ai-bug-hunter' ) ) );
		}

		$diag = ABH_Motor::diagnose( $inc );
		if ( ! $diag ) {
			wp_send_json_error( array( 'message' => __( 'The engine no longer recognizes that issue. Reload the page.', 'ai-bug-hunter' ) ) );
		}

		$diag_path = ! empty( $diag['fix']['path'] ) ? wp_normalize_path( (string) $diag['fix']['path'] ) : '';
		$diag_mode = ! empty( $diag['fix']['mode'] ) ? (int) $diag['fix']['mode'] : 0;
		if ( ! hash_equals( (string) $approved['path'], $diag_path ) || (int) $approved['mode'] !== $diag_mode ) {
			wp_send_json_error( array( 'message' => __( 'The diagnosis changed after the preview. Nothing was applied.', 'ai-bug-hunter' ) ), 409 );
		}

		$res = ABH_Motor::apply_fix( $diag, $key );
		if ( ! $res['ok'] ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Propone añadir el guardián de ABSPATH a un archivo. Sin IA.
	 *
	 * @return void
	 */
	public static function handle_guard_fix() {
		self::guard_request();

		$rel = isset( $_POST['rel'] ) ? sanitize_text_field( wp_unslash( $_POST['rel'] ) ) : '';
		if ( '' === $rel ) {
			wp_send_json_error( array( 'message' => __( 'The file path is missing.', 'ai-bug-hunter' ) ) );
		}

		$res = ABH_Engine::propose_guard( $rel );
		if ( ! $res['ok'] ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Oculta una incidencia sin tocar el registro.
	 *
	 * @return void
	 */
	public static function handle_dismiss() {
		self::guard_request();
		$key = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		if ( '' === $key ) {
			wp_send_json_error( array( 'message' => __( 'The issue reference is missing.', 'ai-bug-hunter' ) ) );
		}
		ABH_Logs::dismiss( $key );
		wp_send_json_success( array( 'message' => __( 'Issue hidden. It will reappear on its own if the error happens again.', 'ai-bug-hunter' ) ) );
	}

	/**
	 * Vuelve a mostrar las incidencias ocultas.
	 *
	 * @return void
	 */
	public static function handle_undismiss() {
		self::guard_request();
		ABH_Logs::undismiss_all();
		wp_send_json_success( array( 'message' => __( 'All issues are shown again.', 'ai-bug-hunter' ) ) );
	}

	/**
	 * Prueba la conexión con el proveedor.
	 *
	 * @return void
	 */
	public static function handle_test() {
		self::guard_request();

		// Si llegan valores del formulario se prueban ESOS, aunque aún no
		// estén guardados. Así «Probar conexión» nunca miente.
		$override = null;
		if ( isset( $_POST['provider'] ) ) {
			$override = array(
				'provider' => sanitize_key( wp_unslash( $_POST['provider'] ) ),
				'model'    => isset( $_POST['model'] ) ? sanitize_text_field( wp_unslash( $_POST['model'] ) ) : '',
				'base_url'                  => isset( $_POST['base_url'] ) ? esc_url_raw( wp_unslash( $_POST['base_url'] ) ) : '',
				'custom_endpoint_confirmed' => isset( $_POST['endpoint_confirmed'] ) && '1' === sanitize_key( wp_unslash( $_POST['endpoint_confirmed'] ) ) ? 1 : 0,
				'allow_private_endpoint'     => isset( $_POST['allow_private'] ) && '1' === sanitize_key( wp_unslash( $_POST['allow_private'] ) ) ? 1 : 0,
				'external_service_consent'  => isset( $_POST['external_service_consent'] ) && '1' === sanitize_key( wp_unslash( $_POST['external_service_consent'] ) ) ? 1 : 0,
			);
			$form_key = isset( $_POST['api_key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) ) : '';
			if ( '' !== $form_key ) {
				// Clave recién escrita: se prueba esa.
				$override['api_key'] = $form_key;
			}
			// El campo vacío solo reutiliza una clave guardada si el proveedor y el endpoint coinciden exactamente.
		}

		$res = ABH_Router::test_connection( $override );
		if ( ! $res['ok'] ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Vacía el registro de errores.
	 *
	 * @return void
	 */
	public static function handle_clear_log() {
		self::guard_request();
		if ( ! ABH_Logs::clear() ) {
			wp_send_json_error( array( 'message' => __( 'The log could not be emptied. It may not have write permissions.', 'ai-bug-hunter' ) ) );
		}
		wp_send_json_success( array( 'message' => __( 'Log emptied.', 'ai-bug-hunter' ) ) );
	}

	/**
	 * Muestra la diferencia entre un archivo del núcleo y el oficial.
	 *
	 * @return void
	 */
	public static function handle_core_file_diff() {
		self::guard_request();
		$rel = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$res = ABH_Core::diff_file( $rel );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Restaura un archivo del núcleo a su contenido oficial.
	 *
	 * @return void
	 */
	public static function handle_core_file_restore() {
		self::guard_request();
		$rel = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		// Aquí NO se pide la frase, y es deliberado. La firma existe para cuando
		// un modelo escribió código que el dueño no leyó entero: lo que se firma
		// es «revisé lo que la IA propuso». Restaurar un archivo del núcleo es lo
		// contrario — pone el archivo oficial de WordPress.org verificado por
		// huella, quitando código desconocido y dejando el conocido — y lo lanza
		// el dueño desde un botón que ya le dice qué va a pasar, con su
		// window.confirm delante. Pedir la misma frase aquí no protegía de nada
		// nuevo: sólo enseñaba a teclearla sin leer, que es justo lo que el
		// encabezado de ABH_Root advierte que la deja de proteger. Y encima la
		// compuerta era INALCANZABLE — sin propuesta pendiente no hay token que
		// firmar, y la huella sintética no la produce ningún payload
		// almacenable —, así que la función quedaba muerta.
		$res = ABH_Core::restore_file( $rel );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Marca una modificación del núcleo como intencional.
	 *
	 * @return void
	 */
	public static function handle_core_file_accept() {
		self::guard_request();
		$rel = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$res = ABH_Core::accept( $rel );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Averigua qué archivo del núcleo debería definir una función ausente.
	 *
	 * @return void
	 */
	public static function handle_core_blame() {
		self::guard_request();
		$fn  = isset( $_POST['fn'] ) ? sanitize_text_field( wp_unslash( $_POST['fn'] ) ) : '';
		$res = ABH_Core::blame_undefined_function( $fn );
		if ( ! is_array( $res ) || empty( $res['ok'] ) ) {
			$necesita = is_array( $res ) && ! empty( $res['need_scan'] );
			// Un «no encontré al culpable» sigue siendo información útil: el
			// motivo concreto vale más que un mensaje genérico.
			$texto = ( is_array( $res ) && ! empty( $res['message'] ) )
				? $res['message']
				: ( $necesita
					? __( 'I need to compare the core with the official one before I can tell you where it comes from. Click «Check core integrity» above and try again.', 'ai-bug-hunter' )
					: __( 'That function is not part of the WordPress core, so a plugin or a theme defines it. Check whether that extension is active and up to date.', 'ai-bug-hunter' ) );
			wp_send_json_error(
				array(
					'need_scan' => $necesita,
					'rel_path'  => ( is_array( $res ) && ! empty( $res['rel_path'] ) ) ? $res['rel_path'] : '',
					'message'   => $texto,
				),
				200
			);
		}
		wp_send_json_success( $res );
	}

	/**
	 * Instala el testigo (mu-plugin).
	 *
	 * @return void
	 */
	public static function handle_watchdog_install() {
		self::guard_request();
		// El testigo es un archivo NUESTRO, fijo, idéntico en toda instalación:
		// no lo escribió ningún modelo, así que no hay parche que revisar y la
		// frase no protege de nada. El aviso de qué es y dónde vive va en el
		// botón, antes de llegar aquí. La compuerta que había era además
		// imposible de pasar, así que instalar el testigo quedaba muerto
		// mientras desinstalarlo seguía abierto: se podía quitar y no volver a
		// poner nunca. Y el testigo es lo único que anota los fatales con el
		// plugin apagado.
		$res = ABH_Watchdog::install();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res, 200 );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Retira el testigo.
	 *
	 * @return void
	 */
	public static function handle_watchdog_uninstall() {
		self::guard_request();
		$res = ABH_Watchdog::uninstall();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res, 200 );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Borra lo que el testigo anotó, sin retirarlo.
	 *
	 * @return void
	 */
	/**
	 * Libera las copias que ya no sirven para revertir nada.
	 *
	 * No borra las de reparaciones recientes: ésas todavía se pueden deshacer, y
	 * quitarles las copias dejando el asiento sería prometer una reversión
	 * imposible.
	 *
	 * @return void
	 */
	public static function handle_health_prune() {
		self::guard_request();
		$res = ABH_Health::prune( 30 );

		$liberado = $res['carpetas'] > 0
			? sprintf(
				/* translators: 1: número de carpetas, 2: espacio liberado. */
				_n( '%2$s was released from %1$d repair that could no longer be rolled back.', '%2$s was released from %1$d repairs that could no longer be rolled back.', $res['carpetas'], 'ai-bug-hunter' ),
				$res['carpetas'],
				size_format( $res['bytes'], 1 )
			)
			: __( 'There was nothing to free up: every saved backup is still usable for reverting.', 'ai-bug-hunter' );

		// Una limpieza que no pudo borrar algo NO es un éxito. ABH_Health::prune()
		// sube los fallos precisamente para que no se descarten aquí: dar por
		// liberado lo que sigue en disco es la avería silenciosa —la carpeta se
		// queda para siempre mientras la pantalla dice que ya no está—. Se
		// responde como error, con estado 200 igual que el resto de fallos
		// lógicos de esta clase, para que el motivo llegue entero a la pantalla.
		$fallo = isset( $res['error'] ) ? (string) $res['error'] : '';
		if ( '' !== $fallo ) {
			wp_send_json_error(
				array(
					'bytes'    => $res['bytes'],
					'carpetas' => $res['carpetas'],
					'errores'  => ( isset( $res['errores'] ) && is_array( $res['errores'] ) ) ? $res['errores'] : array(),
					'message'  => $res['carpetas'] > 0
						? sprintf(
							/* translators: 1: lo que sí se liberó, 2: motivo del fallo. */
							__( '%1$s Some copies could not be deleted and are still on disk: %2$s', 'ai-bug-hunter' ),
							$liberado,
							$fallo
						)
						: sprintf(
							/* translators: %s: motivo del fallo. */
							__( 'Nothing could be released: %s', 'ai-bug-hunter' ),
							$fallo
						),
				),
				200
			);
		}

		wp_send_json_success( array(
			'bytes'    => $res['bytes'],
			'carpetas' => $res['carpetas'],
			'message'  => $liberado,
		) );
	}

	public static function handle_watchdog_clear() {
		self::guard_request();
		wp_send_json_success( ABH_Watchdog::clear() );
	}

	/**
	 * Sincroniza a mano el feed de vulnerabilidades del núcleo.
	 *
	 * @return void
	 */
	public static function handle_cve_refresh() {
		self::guard_request();
		$res = ABH_CVE::refresh();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res, 200 );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Inicia la comprobación de integridad del núcleo de WordPress.
	 *
	 * @return void
	 */
	public static function handle_core_scan_start() {
		self::guard_request();
		$res = ABH_Core::scan_start();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Comprueba un lote de archivos del núcleo.
	 *
	 * @return void
	 */
	public static function handle_core_scan_step() {
		self::guard_request();
		$res = ABH_Core::scan_step();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Webchat de HUNTER AI. Responde; nunca ejecuta.
	 *
	 * @return void
	 */
	public static function handle_chat() {
		self::guard_request();
		if ( ! ABH_Chat::allowed() ) {
			// Dice lo que de verdad se exige: administrar el sitio, y en
			// multisitio administrar la red. Un mensaje que promete un candado
			// distinto del que hay es una mentira en pantalla, y las mentiras en
			// pantalla son las que hacen que nadie se fíe del resto.
			wp_send_json_error( array( 'message' => __( 'HUNTER AI chat is reserved for whoever administers the site.', 'ai-bug-hunter' ) ), 403 );
		}
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		$raw = isset( $_POST['messages'] ) ? (string) wp_unslash( $_POST['messages'] ) : '[]'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Bounded JSON is decoded and ABH_Chat validates every role/content pair.
		if ( strlen( $raw ) > 102400 ) {
			wp_send_json_error( array( 'message' => __( 'The conversation is too long. Start a new one.', 'ai-bug-hunter' ) ), 413 );
		}
		$messages = json_decode( $raw, true );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $messages ) ) {
			wp_send_json_error( array( 'message' => __( 'The conversation does not have a valid format.', 'ai-bug-hunter' ) ), 400 );
		}
		$res = ABH_Chat::ask( $messages, $job );

		// La puerta puede haberse cerrado mientras se respondía: el trabajo
		// terminó, o quedó resuelto. Esta ruta no pasa por thoth_reply(), así
		// que sin esto la terminal seguiría abierta hasta la siguiente
		// respuesta del flujo. Va también en el error, por el mismo motivo.
		$res['chat_open'] = (bool) ( ABH_Chat::allowed() && ABH_Chat::open_for( $job ) );

		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Cierra el ciclo: reejecuta el detector y dictamina si quedó resuelto.
	 *
	 * @return void
	 */
	public static function handle_thoth_verify() {
		self::guard_request();
		$job = isset( $_POST['job'] ) ? sanitize_text_field( wp_unslash( $_POST['job'] ) ) : '';
		if ( '' === $job ) {
			wp_send_json_error( array( 'message' => __( 'The job reference is missing.', 'ai-bug-hunter' ) ) );
		}
		$res = ABH_Thoth_AI::verify_repair( $job );
		self::thoth_reply( $res );
	}

	/**
	 * Limpia del registro solo las entradas de errores ya resueltos.
	 *
	 * @return void
	 */
	public static function handle_purge_resolved() {
		self::guard_request();
		$dry = isset( $_POST['dry_run'] ) && '1' === sanitize_key( wp_unslash( $_POST['dry_run'] ) );
		$res = ABH_Logs::purge_resolved( $dry );
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res );
		}
		wp_send_json_success( $res );
	}

	/**
	 * Borra respaldos e historial.
	 *
	 * @return void
	 */
	public static function handle_purge() {
		self::guard_request();
		// La purga puede negarse: si hay una transacción a medias, sus copias son
		// la única marcha atrás que queda. Antes se anunciaba «borrados» pasara
		// lo que pasara, así que una negativa se leía en pantalla como un éxito.
		$res = ABH_Backup::purge();
		if ( empty( $res['ok'] ) ) {
			wp_send_json_error( $res, 409 );
		}
		wp_send_json_success( $res );
	}
}
