/* global jQuery, ABH, Blob, URL */
( function ( $ ) {
	'use strict';

	// .text().html() escapa & < >, pero deja pasar las comillas. Un texto de log
	// con una comilla doble cerraba el atributo y colaba otro atributo nuevo, así
	// que aquí se escapa también " y ', igual que hace escCore más abajo.
	function esc( s ) {
		return String( s === null || s === undefined ? '' : s ).replace( /[&<>"']/g, function ( c ) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ];
		} );
	}

	// Defensa en profundidad contra el XSS almacenado de la cadena A1.
	//
	// esc() ya escapa las comillas, pero un escapador es una sola línea de
	// defensa y en esta misma pantalla hay @keyframes con nombre: un atributo
	// colado (onanimationstart) dispara solo, sin que nadie pulse nada. Por eso
	// todo valor que venga del servidor y acabe DENTRO de un atributo se pone
	// con .attr()/.text() sobre un nodo real: el escapado lo hace el navegador
	// y un valor no puede cerrar el atributo aunque el escapador fallara.
	//
	// Se devuelve marcado porque quien llama sigue concatenando cadenas; el nodo
	// ya está construido y serializado por el DOM, así que sale correcto.
	function nodeHtml( $node ) {
		return ( $node && $node.length ) ? ( $node.prop( 'outerHTML' ) || '' ) : '';
	}

	// Los avisos de otros plugins ya no se tocan desde aquí. Antes este archivo
	// los BORRABA del DOM —y volvía a borrarlos con un MutationObserver— cazando
	// además cualquier aviso que sólo enlazara a la pantalla de TGMPA, o sea
	// también avisos ajenos legítimos. Destruir la salida de otro plugin es
	// motivo de rechazo en la revisión. Si nuestras pantallas tienen que verse
	// ordenadas, eso se resuelve en assets/admin.css plegándolos visualmente y
	// sólo dentro de nuestras pantallas: el nodo sigue vivo y en su sitio.

	// Un aviso único arriba de la página. Se reemplaza, no se acumula: diez
	// avisos iguales no informan más que uno.
	function showRequestError( message ) {
		var $root = $( '#wpbody-content' );
		if ( ! $root.length ) { $root = $( 'body' ); }
		var $notice = $( '#abh-request-error' );
		if ( ! $notice.length ) {
			$notice = $( '<div class="notice notice-error abh-request-error" id="abh-request-error"><p></p></div>' );
			$root.prepend( $notice );
		}
		$notice.find( 'p' ).first().text( message );
		$notice.show();
	}

	function requestErrorText( jqXHR ) {
		var status = jqXHR && jqXHR.status ? jqXHR.status : 0;
		if ( ! status ) {
			return 'The request could not be sent. Check your connection and try again. Nothing was changed.';
		}
		return 'The request failed (HTTP ' + status + '). Nothing was changed. Reload the page and try again; if it persists, report it to the plugin author.';
	}

	// Un fallo se cuenta UNA sola vez.
	//
	// El aviso de arriba existe para las acciones que al fallar no dicen nada:
	// el botón vuelve a su sitio y nadie sabe por qué no pasó nada. Pero cuando
	// quien llama YA pinta su propio mensaje —advise() con su .abh-msg-err,
	// request() con la línea roja de la consola, rollback con su párrafo bajo el
	// botón— el aviso global escribía un segundo mensaje por el mismo fallo.
	// Reclamar la petición apaga sólo el aviso global; el mensaje propio queda.
	function claimFailure( xhr ) {
		if ( xhr ) { xhr.abhFailureShown = true; }
		return xhr;
	}

	function post( action, data ) {
		var xhr = $.post(
			ABH.ajax,
			$.extend( { action: 'abh_' + action, nonce: ABH.nonce }, data || {} )
		);
		// Se reclama antes de que exista respuesta, así que aquí basta con mirar
		// la marca: no hace falta adivinar qué .fail() se registró después.
		xhr.fail( function ( jqXHR ) {
			if ( xhr.abhFailureShown ) { return; }
			showRequestError( requestErrorText( jqXHR ) );
		} );
		return xhr;
	}

	function renderDiff( rows ) {
		if ( ! rows || ! rows.length ) {
			return '<p class="abh-muted">' + esc( ABH.i18n.sin_cambios ) + '</p>';
		}
		// El tipo de fila venía del servidor y entraba en el atributo class por
		// concatenación; los números de línea entraban además SIN escapar. Ahora
		// la fila se construye como nodo: addClass() y .text() no pueden cerrar
		// un atributo ni abrir una etiqueta.
		var $wrap  = $( '<div class="abh-diff"></div>' );
		var $table = $( '<table></table>' ).appendTo( $wrap );
		rows.forEach( function ( r ) {
			var sign = r.type === 'add' ? '+' : ( r.type === 'del' ? '-' : '' );
			var $tr = $( '<tr></tr>' ).addClass( String( r.type || '' ) );
			$tr.append( $( '<td class="ln"></td>' ).text( r.old ? r.old : '' ) );
			$tr.append( $( '<td class="ln"></td>' ).text( r.new ? r.new : '' ) );
			$tr.append( $( '<td class="sign"></td>' ).text( sign ) );
			$tr.append( $( '<td></td>' ).text( String( r.text === null || r.text === undefined ? '' : r.text ) ) );
			$table.append( $tr );
		} );
		return nodeHtml( $wrap );
	}

	function renderFindings( findings ) {
		if ( ! findings || ! findings.length ) {
			return '';
		}
		var html = '<div class="abh-findings">';
		findings.forEach( function ( f ) {
			var cls = f.severity === 'warn' ? 'abh-finding warn' : 'abh-finding';
			var mark = f.severity === 'warn' ? '⚠️' : '⛔';
			html += '<div class="' + cls + '">' +
				'<strong>' + mark + ' ' + esc( f.code ) + ' — ' + esc( f.titulo ) + '</strong>' +
				'<p>' + esc( f.explicacion ) + '</p>';
			if ( f.evidence ) {
				html += '<code>' + esc( String( f.evidence ).substring( 0, 160 ) ) + '</code>';
			}
			html += '</div>';
		} );
		return html + '</div>';
	}

	function renderExplicacion( x ) {
		if ( ! x ) {
			return '';
		}
		var html = '';
		if ( x.tipo === 'sintoma' ) {
			html += '<div class="abh-tape"><strong>⚠️ This change does not remove the underlying cause</strong>' +
				'<p>It may make the notice disappear, but the real problem would remain. HUNTER AI flags this so silence is not mistaken for a repair.</p></div>';
		}
		var blocks = [
			{ k: 'que_pasa', t: 'What is happening' },
			{ k: 'causa_raiz', t: 'Underlying cause' },
			{ k: 'que_hace', t: 'What the change will do' },
			{ k: 'que_no', t: 'What it does not solve', cls: 'abh-x-warn' },
			{ k: 'riesgos', t: 'Risks' },
			{ k: 'verificacion', t: 'How to check it' }
		];
		var body = '';
		blocks.forEach( function ( b ) {
			if ( x[ b.k ] ) {
				body += '<div class="abh-x-item ' + ( b.cls || '' ) + '"><h4>' + esc( b.t ) + '</h4><p>' + esc( x[ b.k ] ) + '</p></div>';
			}
		} );
		return html + ( body ? '<div class="abh-x">' + body + '</div>' : '' );
	}

	function renderUso( d ) {
		var m = d.meter;
		if ( m && ( m.total || m.avoided_total ) ) {
			var linea = m.label || '';
			if ( m.cost ) { linea += ' Actual cost ' + m.cost + '.'; }
			if ( m.avoided_total ) {
				linea += ' You saved about ' + Number( m.avoided_total ).toLocaleString( 'en-US' ) + ' tokens by resolving it without the model.';
			}
			return '<p class="abh-uso">' + esc( linea ) + '</p>';
		}
		var u = d.usage_total || d.usage;
		if ( ! u || ( ! u.in && ! u.out ) ) {
			return '';
		}
		var txt = 'Cumulative usage: ' + ( u.in || 0 ) + ' input tokens + ' + ( u.out || 0 ) + ' output tokens';
		if ( d.cost_total || d.cost ) {
			txt += ' · approximately ' + ( d.cost_total || d.cost ) + '.';
		}
		return '<p class="abh-uso">' + esc( txt ) + '</p>';
	}


	// El navegador ya no lleva la cuenta: el servidor manda un único medidor
	// por incidencia y aquí solo se guarda el último que llegó. Antes esta
	// función hacía `usage_total || usage`, así que cuando una respuesta traía
	// el consumo de un paso suelto el acumulado se reemplazaba por él y el
	// número bajaba solo. De ahí venía el acumulado incorrecto.
	function rememberUsage( d ) {
		if ( ! d ) { return; }
		if ( d.meter ) {
			repair.meter = d.meter;
			repair.usage = { in: Number( d.meter.usage.in || 0 ), out: Number( d.meter.usage.out || 0 ) };
			repair.cost  = d.meter.cost || '';
			return;
		}
		var u = d.usage_total;
		if ( u ) {
			repair.usage = { in: Number( u.in || 0 ), out: Number( u.out || 0 ) };
		}
		if ( d.cost_total ) {
			repair.cost = d.cost_total;
		}
	}

	function usageSummaryLine( title ) {
		var m = repair.meter;
		if ( m && ( m.total || m.avoided_total ) ) {
			var detail = m.label || '';
			if ( m.total ) {
				detail += ' Breakdown: ' + Number( m.usage.in || 0 ) + ' input and ' + Number( m.usage.out || 0 ) + ' output tokens across ' + Number( m.calls || 0 ) + ' request(s).';
			}
			if ( m.cost ) { detail += ' Estimated actual cost: ' + m.cost + '.'; }
			if ( m.total ) { detail += ' Provider billing depends on your configured provider and account; AI Bug Hunter does not include a free token allowance.'; }
			if ( m.avoided_total ) {
				detail += ' Savings compared with the full cycle: about ' + Number( m.avoided_total ).toLocaleString( 'en-US' ) + ' tokens.';
			}
			return consoleLine( 'info', title || 'Cumulative usage', detail );
		}
		var u = repair.usage || { in: 0, out: 0 };
		var d2 = 'Cumulative requests: ' + Number( u.in || 0 ) + ' input tokens and ' + Number( u.out || 0 ) + ' output tokens.';
		if ( repair.cost ) {
			d2 += ' Estimated cost: ' + repair.cost + '.';
		}
		if ( ! u.in && ! u.out && ! repair.cost ) {
			d2 = 'The provider did not return usage metrics for this run.';
		}
		return consoleLine( 'info', title || 'Cumulative usage', d2 );
	}

	function busy( $btn, text ) {
		$btn.prop( 'disabled', true );
		$btn.siblings( '.abh-spinner' ).remove();
		$btn.after( '<span class="abh-spinner">' + esc( text ) + '</span>' );
	}

	function done( $btn ) {
		$btn.prop( 'disabled', false );
		$btn.siblings( '.abh-spinner' ).remove();
	}

	// La reproducción ya no debe decidir cuándo empieza la siguiente llamada.
	// Las primeras tres sesiones conservan la narración; desde la cuarta el
	// ritmo rápido se selecciona automáticamente.
	var normalPaceFactor = 1;
	var paceStorageKey = 'abh_console_analysis_runs_v1';

	function adaptiveConsolePace( mode ) {
		if ( mode !== 'thoth' ) {
			return { pace: 'fast', ordinal: 0, automatic: true };
		}
		var count = 0;
		try {
			count = parseInt( window.localStorage.getItem( paceStorageKey ) || '0', 10 ) || 0;
			count += 1;
			window.localStorage.setItem( paceStorageKey, String( count ) );
		} catch ( ignore ) {
			count = 1;
		}
		return { pace: count > 3 ? 'fast' : 'normal', ordinal: count, automatic: true };
	}

	var repair = {
		job: '', scanId: '', key: '', token: '', envToken: '', path: '', sha: '', diff: [], logs: [],
		$source: null, $card: null, mode: 'thoth', result: null, closed: false,
		messageQueue: [], messageActive: false, queueEpoch: 0, pace: 'normal', paceAuto: true, sessionOrdinal: 0, flushMessages: false, wakeMessage: null,
		panelSections: {}, panelOrder: [], environmentType: '', reportBusy: false, lastFailure: {}, manualGuide: null, usage: { in: 0, out: 0 }, cost: '', meter: null, evidenceFirst: false, uiPaused: false, autoScroll: true, activeTab: 'analysis', verified: false,
		startedAt: 0, firstUsefulAt: 0, preliminary: null
	};

	function stamp() {
		var d = new Date();
		return [ d.getHours(), d.getMinutes(), d.getSeconds() ].map( function ( n ) {
			return String( n ).padStart( 2, '0' );
		} ).join( ':' );
	}

	function setProgress( value ) {
		$( '#abh-console-progress-bar' ).css( 'width', Math.max( 0, Math.min( 100, value ) ) + '%' );
	}

	function resolvedPromise() {
		return $.Deferred().resolve().promise();
	}

	function scrollConsole( force ) {
		var $terminal = $( '#abh-console-terminal' );
		if ( ! force && ! repair.autoScroll ) { return; }
		if ( $terminal.length && $terminal[ 0 ] ) {
			$terminal.scrollTop( $terminal[ 0 ].scrollHeight );
		}
	}

	function messageWait( milliseconds, epoch ) {
		var deferred = $.Deferred();
		if ( repair.closed || repair.flushMessages || epoch !== repair.queueEpoch || milliseconds <= 0 ) {
			deferred.resolve();
			return deferred.promise();
		}

		var remaining = milliseconds;
		var started = Date.now();
		var timer = null;

		function resumeWhenVisible() {
			if ( repair.closed || repair.flushMessages || epoch !== repair.queueEpoch ) {
				deferred.resolve();
				return;
			}
			if ( repair.uiPaused ) {
				timer = window.setTimeout( resumeWhenVisible, 100 );
				return;
			}
			started = Date.now();
			timer = window.setTimeout( function () {
				repair.wakeMessage = null;
				deferred.resolve();
			}, Math.max( 0, remaining ) );
		}

		repair.wakeMessage = function () {
			if ( timer ) { window.clearTimeout( timer ); }
			remaining = Math.max( 0, remaining - ( Date.now() - started ) );
			repair.wakeMessage = null;
			deferred.resolve();
		};
		resumeWhenVisible();
		return deferred.promise();
	}

	function typingDelay( part ) {
		if ( repair.flushMessages ) {
			return 0;
		}
		if ( repair.pace === 'fast' ) {
			return part === 'title' ? 4 : 2;
		}
		if ( part === 'title' ) {
			return Math.round( 15 * normalPaceFactor );
		}
		if ( part === 'code' ) {
			return Math.round( 3 * normalPaceFactor );
		}
		return Math.round( 6 * normalPaceFactor );
	}

	function typeText( $target, text, part, epoch ) {
		var deferred = $.Deferred();
		var value = String( text || '' );
		var index = 0;
		if ( ! value ) {
			deferred.resolve();
			return deferred.promise();
		}

		function step() {
			if ( repair.closed || epoch !== repair.queueEpoch ) {
				deferred.resolve();
				return;
			}
			if ( repair.flushMessages ) {
				$target.text( value );
				scrollConsole();
				deferred.resolve();
				return;
			}
			var chunk = repair.pace === 'fast' ? 4 : 1;
			index = Math.min( value.length, index + chunk );
			$target.text( value.substring( 0, index ) );
			scrollConsole();
			if ( index >= value.length ) {
				deferred.resolve();
				return;
			}
			messageWait( typingDelay( part ), epoch ).then( step );
		}

		step();
		return deferred.promise();
	}

	function pauseAfterLine( type ) {
		if ( repair.flushMessages ) {
			return 0;
		}
		if ( repair.pace === 'fast' ) {
			return 90;
		}
		if ( type === 'ai' || type === 'warn' || type === 'error' ) {
			return Math.round( 650 * normalPaceFactor );
		}
		if ( type === 'work' ) {
			return Math.round( 480 * normalPaceFactor );
		}
		return Math.round( 360 * normalPaceFactor );
	}

	function renderQueuedLine( task ) {
		var labels = { ok: 'READY', work: 'IN PROGRESS', info: 'INFO', warn: 'WARNING', error: 'STOP', motor: 'MOTOR', ai: 'HUNTER AI', you: 'YOU' };
		var entry = task.entry;
		var epoch = task.epoch;
		var accessible = '[' + entry.time + '] ' + ( labels[ entry.type ] || 'INFO' ) + '. ' + entry.title;
		if ( entry.detail ) { accessible += '. ' + entry.detail; }
		if ( entry.code ) { accessible += '. ' + entry.code; }
		var html = '<div class="abh-console-line is-typing">' +
			'<span class="abh-console-time" aria-hidden="true">[' + esc( entry.time ) + ']</span>' +
			'<span class="abh-console-label" aria-hidden="true">' + esc( labels[ entry.type ] || 'INFO' ) + '</span>' +
			'<div class="abh-console-copy" aria-hidden="true"><strong></strong>';
		if ( entry.detail ) { html += '<p></p>'; }
		if ( entry.code ) { html += '<code></code>'; }
		html += '</div></div>';

		var $terminal = $( '#abh-console-terminal' );
		var $line = $( html );
		// Misma regla que el aria-label: el tipo de línea decora el class y se
		// pone con addClass(), no concatenado dentro del atributo.
		$line.addClass( 'is-' + String( entry.type || 'info' ) );
		// El texto accesible sale de una línea de log que puede venir de fuera.
		// Puesto por DOM lo escapa el navegador entero, así que no hay forma de
		// cerrar el atributo y abrir otro aunque el escape de arriba fallara.
		$line.attr( 'aria-label', accessible );
		$terminal.append( $line );
		scrollConsole();
		$( '#abh-console-download-log' ).prop( 'disabled', false );

		// Lo que escribió la persona se pinta de golpe. Teclear letra a letra
		// algo que acaba de escribir ella es teatro, y encima retrasa la
		// respuesta. Solo HUNTER «escribe» en pantalla.
		if ( 'you' === entry.type ) {
			$line.find( 'strong' ).text( entry.title );
			if ( entry.detail ) { $line.find( 'p' ).text( entry.detail ); }
			$line.removeClass( 'is-typing' ).addClass( 'is-complete' );
			scrollConsole();
			return resolvedPromise();
		}

		return messageWait( repair.pace === 'fast' ? 20 : Math.round( 130 * normalPaceFactor ), epoch )
			.then( function () { return typeText( $line.find( 'strong' ), entry.title, 'title', epoch ); } )
			.then( function () { return entry.detail ? typeText( $line.find( 'p' ), entry.detail, 'detail', epoch ) : resolvedPromise(); } )
			.then( function () { return entry.code ? typeText( $line.find( 'code' ), entry.code, 'code', epoch ) : resolvedPromise(); } )
			.then( function () {
				$line.removeClass( 'is-typing' ).addClass( 'is-complete' );
				return messageWait( pauseAfterLine( entry.type ), epoch );
			} );
	}

	function pumpConsoleQueue() {
		if ( repair.messageActive || ! repair.messageQueue.length ) {
			return;
		}
		repair.messageActive = true;
		var task = repair.messageQueue.shift();
		renderQueuedLine( task ).always( function () {
			repair.messageActive = false;
			task.deferred.resolve();
			pumpConsoleQueue();
		} );
	}

	function consoleLine( type, title, detail, code ) {
		var deferred = $.Deferred();
		var entry = { time: stamp(), type: type || 'info', title: title || '', detail: detail || '', code: code || '' };
		// Se registra al encolar, no al acabar de animar. El análisis puede
		// continuar y el reporte sigue incluyendo cada evento en orden.
		repair.logs.push( entry );
		repair.messageQueue.push( {
			epoch: repair.queueEpoch,
			deferred: deferred,
			entry: entry
		} );
		pumpConsoleQueue();
		return deferred.promise();
	}

	function consoleSequence( lines ) {
		var pending = [];
		( lines || [] ).forEach( function ( line ) {
			pending.push( consoleLine( line[ 0 ], line[ 1 ], line[ 2 ], line[ 3 ] ) );
		} );
		return pending.length ? pending[ pending.length - 1 ] : resolvedPromise();
	}

	function updatePaceLabel() {
		var label = repair.flushMessages
			? 'No animation'
			: ( repair.paceAuto
				? ( repair.pace === 'fast' ? 'Automatic pace · fast' : 'Automatic pace · narrated' )
				: ( repair.pace === 'fast' ? 'Fast pace' : 'Narrated pace' ) );
		$( '#abh-console-pace-status' ).text( label );
		$( '#abh-console-toggle-pace' ).text( repair.pace === 'fast' ? 'Narrated view' : 'Speed up' );
	}

	function flushConsoleMessages() {
		repair.flushMessages = true;
		repair.pace = 'fast';
		if ( repair.wakeMessage ) { repair.wakeMessage(); }
		updatePaceLabel();
	}

	function cancelConsoleMessages() {
		repair.queueEpoch += 1;
		repair.flushMessages = true;
		if ( repair.wakeMessage ) { repair.wakeMessage(); }
		while ( repair.messageQueue.length ) {
			repair.messageQueue.shift().deferred.resolve();
		}
	}

	function setConsoleView( name ) {
		name = name === 'events' ? 'events' : 'analysis';
		repair.activeTab = name;
		$( '[data-console-tab]' ).each( function () {
			var active = $( this ).data( 'console-tab' ) === name;
			$( this ).toggleClass( 'is-active', active ).attr( 'aria-selected', active ? 'true' : 'false' );
		} );
		$( '[data-console-view]' ).each( function () {
			var active = $( this ).data( 'console-view' ) === name;
			$( this ).toggleClass( 'is-active', active ).prop( 'hidden', ! active );
		} );
	}

	function summaryList( items, limit ) {
		var list = Array.isArray( items ) ? items.filter( Boolean ) : [];
		if ( limit ) { list = list.slice( 0, limit ); }
		return list.length ? '<ul>' + list.map( function ( item ) { return '<li>' + esc( item ) + '</li>'; } ).join( '' ) + '</ul>' : '<p class="abh-console-summary-empty">There is no confirmed data for this section yet.</p>';
	}

	function updateSummaryCard( slot, html, meta, tone ) {
		var $card = $( '[data-console-summary="' + slot + '"]' );
		var $body = $( '#abh-console-summary-' + slot );
		if ( ! $card.length || ! $body.length ) { return; }
		$card.removeClass( 'is-info is-warning is-ok is-stop is-updated' );
		if ( tone ) { $card.addClass( tone ); }
		$body.html( html || '<p class="abh-console-summary-empty">No data available.</p>' );
		if ( meta && meta.selector ) { $( meta.selector ).text( meta.text || '' ); }
		window.requestAnimationFrame( function () {
			$card.addClass( 'is-updated' );
			window.setTimeout( function () { $card.removeClass( 'is-updated' ); }, 900 );
		} );
	}

	function resetConsoleSummary() {
		updateSummaryCard( 'hypothesis', '<p>HUNTER AI will show here what it believes is happening and which questions remain open.</p>', { selector: '#abh-console-confidence', text: 'Confidence: pending' }, '' );
		updateSummaryCard( 'cause', '<p>Pending confirmation with evidence from the code and the environment.</p>', null, '' );
		updateSummaryCard( 'evidence', '<p>Verified evidence will appear as the review progresses.</p>', null, '' );
		updateSummaryCard( 'plan', '<p>The plan will appear after Analyst, Skeptic and Referee finish their review.</p>', { selector: '#abh-console-plan-state', text: 'No changes applied' }, '' );
		updateSummaryCard( 'risk', '<p>No severity will be assigned until there is enough evidence.</p>', { selector: '#abh-console-risk-state', text: 'Pending evaluation' }, '' );
	}

	function renderLocalPreliminary( preliminary ) {
		if ( ! preliminary || 'object' !== typeof preliminary ) { return; }
		repair.preliminary = preliminary;
		repair.firstUsefulAt = repair.firstUsefulAt || Date.now();
		var elapsed = Math.max( 0, ( repair.firstUsefulAt - repair.startedAt ) / 1000 );
		var evidence = Array.isArray( preliminary.evidence ) ? preliminary.evidence : [];
		updateSummaryCard(
			'hypothesis',
			'<p><strong>' + esc( preliminary.title || 'Lectura local preliminar' ) + '</strong></p><p>' + esc( preliminary.summary || '' ) + '</p>',
			{ selector: '#abh-console-confidence', text: ( preliminary.confidence || 'Local preliminary' ) + ' · ' + elapsed.toFixed( 1 ) + ' s' },
			'is-info'
		);
		updateSummaryCard(
			'cause',
			'<p>' + esc( preliminary.cause || '' ) + '</p><p class="abh-console-summary-note">This is not yet a conclusion and does not authorize changes.</p>',
			null,
			'is-info'
		);
		if ( evidence.length ) {
			updateSummaryCard( 'evidence', summaryList( evidence, 3 ), null, 'is-ok' );
		}
		setConsoleState( 'Local reading ready · checking against evidence', 'is-working' );
	}

	function titleFromSlug( slug ) {
		var acronyms = { ai: 'AI', wp: 'WP', api: 'API', php: 'PHP', abh: 'ABH', llm: 'LLM' };
		return String( slug || '' ).split( /[-_]+/ ).filter( Boolean ).map( function ( part ) {
			var low = part.toLowerCase();
			return acronyms[ low ] || low.charAt( 0 ).toUpperCase() + low.slice( 1 );
		} ).join( ' ' );
	}

	function consolePathContext( path ) {
		var value = String( path || '' );
		if ( /^https?:\/\//i.test( value ) ) {
			var host = '';
			try { host = new window.URL( value ).host; } catch ( ignore ) {}
			return { target: host || 'URL', route: value };
		}
		var plugin = value.match( /^wp-content\/plugins\/([^/]+)(?:\/(.*))?$/i );
		if ( plugin ) {
			return { target: 'Plugin · ' + titleFromSlug( plugin[ 1 ] ), route: plugin[ 2 ] || plugin[ 1 ] };
		}
		var theme = value.match( /^wp-content\/themes\/([^/]+)(?:\/(.*))?$/i );
		if ( theme ) {
			return { target: 'Tema · ' + titleFromSlug( theme[ 1 ] ), route: theme[ 2 ] || theme[ 1 ] };
		}
		return { target: '', route: value || ( repair.mode === 'scan' ? 'PHP file scan' : 'Pending identification' ) };
	}

	function syncConsoleContext() {
		var context = consolePathContext( repair.path );
		var mode = repair.mode === 'scan' ? 'Local scan · Read only' : ( repair.mode === 'guard' || repair.mode === 'env' ? 'Local repair · Safe plan' : 'Analysis · Safe plan' );
		if ( context.target ) { $( '#abh-console-target' ).text( context.target ).attr( 'title', context.target ); }
		$( '#abh-console-route' ).text( context.route ).attr( 'title', context.route );
		$( '#abh-console-mode' ).text( mode );
		$( '#abh-console-fingerprint' ).text( repair.sha ? 'sha256: ' + String( repair.sha ).slice( 0, 12 ) + '…' + String( repair.sha ).slice( -8 ) : 'Pending' );
	}

	function setConsoleState( text, cls ) {
		$( '#abh-console-state' ).attr( 'class', 'abh-console-state ' + ( cls || '' ) ).text( text );
		var stateClass = 'is-working';
		if ( /error|fall|bloque|no resuelto/i.test( text ) || cls === 'is-error' ) { stateClass = 'is-error'; }
		else if ( /esper|pending|revisi|parcial/i.test( text ) || cls === 'is-warning' || cls === 'is-waiting' || cls === 'is-warn' ) { stateClass = 'is-warning'; }
		else if ( /resuelto|completo|correct|seguro|sin cambios|nada que reparar/i.test( text ) || cls === 'is-done' || cls === 'is-safe' ) { stateClass = 'is-ok'; }
		$( '#abh-console-scan-state' ).attr( 'class', stateClass ).html( '<span aria-hidden="true"></span>' + esc( text ) );
		if ( /aplicado|modific/i.test( text ) && ! /sin cambios|no se modific/i.test( text ) ) {
			$( '#abh-console-plan-state' ).text( 'Change applied' );
		}
	}

	function reportActionButtons() {
		if ( repair.mode !== 'thoth' || ! repair.job ) {
			return '';
		}
		return '<button type="button" class="button" id="abh-console-download-report">Download report</button>' +
			'<button type="button" class="button" id="abh-console-open-report">Open / save PDF</button>';
	}

	function setManualGuideInline( visible, label ) {
		$( '#abh-console-manual-guide-inline' )
			.prop( 'hidden', ! visible )
			.prop( 'disabled', false )
			.text( label || 'What should I do?' );
	}

	function setActions( html ) {
		$( '#abh-console-actions' ).html( reportActionButtons() + ( html || '' ) );
		// console-fx refleja la acción constructiva junto al prompt. Esperar al
		// latido periódico podía dejar el botón invisible durante una transición
		// rápida, especialmente después de recuperar un contrato. El evento hace
		// que el espejo se actualice en el mismo turno en que cambia el pie.
		document.dispatchEvent( new CustomEvent( 'abh:console-actions-changed' ) );
	}

	function postApplyActions() {
		var urls = ABH.urls || {};
		var html = '<button type="button" class="button" id="abh-console-download-log">Download log</button>';
		// Las tres direcciones llegan del servidor y acababan dentro de href por
		// concatenación. Se ponen con .attr() sobre el enlace ya creado.
		if ( urls.site ) {
			html += nodeHtml( $( '<a class="button" target="_blank" rel="noopener noreferrer"></a>' )
				.attr( 'href', urls.site )
				.text( 'Open site and repeat the test' ) );
		}
		if ( urls.diagnostic ) {
			// Navegar recarga la página y mata la consola: se avisa antes para
			// que nadie pierda el reporte o el registro sin haberlos guardado.
			html += nodeHtml( $( '<a class="button abh-leave-console"></a>' )
				.attr( 'href', urls.diagnostic )
				.text( 'Review diagnosis' ) );
		}
		if ( urls.history ) {
			html += nodeHtml( $( '<a class="button abh-leave-console"></a>' )
				.attr( 'href', urls.history )
				.text( 'History and rollback' ) );
		}
		return html + '<button type="button" class="button button-primary" data-console-close>Finish</button>';
	}

	function updateResolvedCounters() {
		var active = $( '.abh-incident' ).not( '.abh-is-solved, [data-resolved-ui="1"]' ).length;
		$( '.abh-hero-stat' ).each( function () {
			var $stat = $( this );
			var label = $.trim( $stat.find( 'b' ).first().text() ).toLowerCase();
			var $count = $stat.find( '[data-abh-count]' ).first();
			if ( /pending/.test( label ) && $count.length ) { $count.attr( 'data-abh-count', active ).text( active ); }
			if ( /resuelto/.test( label ) && $count.length ) {
				var value = ( parseInt( $count.attr( 'data-abh-count' ), 10 ) || parseInt( $count.text(), 10 ) || 0 ) + 1;
				$count.attr( 'data-abh-count', value ).text( value );
			}
		} );
		$( '.abh-summary-list dt' ).filter( function () { return /problemas detectados/i.test( $( this ).text() ); } ).next( 'dd' ).text( active );
	}

	function refreshFindingWorkspace() {
		$( '.abh-finding-workspace' ).each( function () {
			var $workspace = $( this );
			var $slides = $workspace.find( '.abh-finding-slide' );
			var count = $slides.length;
			$workspace.attr( 'data-finding-count', count );
			$slides.each( function ( index ) { $( this ).attr( 'data-finding-index', index ).prop( 'hidden', 0 !== index ); } );
			var $nav = $workspace.find( '.abh-finding-nav' );
			if ( count ) {
				$nav.show().find( 'span' ).first().html( '<b data-finding-current>1</b> of ' + count );
				var $first = $slides.first();
				$workspace.find( '[data-active-severity]' ).text( $first.data( 'finding-severity' ) || '' ).attr( 'class', 'abh-severity-pill is-' + ( $first.data( 'finding-tone' ) || 'warning' ) + '' ).show();
			} else {
				$nav.hide();
				$workspace.find( '[data-active-severity]' ).hide();
				$workspace.find( '.abh-finding-stage' ).html( '<div class="abh-clean-state"><span class="dashicons dashicons-shield-alt"></span><div><h2>There are no active findings</h2><p>The repair was verified and the finding was removed from the active list.</p></div></div>' );
			}
		} );
	}

	function resolveIncidentInUi( key ) {
		var wanted = String( key || '' );
		if ( ! wanted ) { return; }
		var $matches = $( '.abh-incident' ).filter( function () { return String( $( this ).attr( 'data-key' ) || $( this ).data( 'key' ) || '' ) === wanted; } );
		$matches.each( function () {
			var $item = $( this );
			if ( $item.hasClass( 'abh-finding-slide' ) ) { $item.remove(); }
			else { $item.attr( 'data-resolved-ui', '1' ).stop( true, true ).slideUp( 180, function () { $( this ).remove(); updateResolvedCounters(); } ); }
		} );
		refreshFindingWorkspace();
		updateResolvedCounters();
	}

	// Cierre del ciclo: aplicar no es reparar. Se reejecuta el detector y solo
	// entonces se dice RESUELTO. Es determinista y no consume tokens.
	function verifyRepair( applied ) {
		return request( 'thoth_verify', { job: repair.job } )
			.then( function ( v ) {
				// Verificado: el trabajo deja de admitir preguntas. Es el otro
				// extremo de la compuerta y hasta ahora nunca se aplicaba.
				syncPrompt( v );
				rememberUsage( v );
				var resuelto = 'verified' === v.verdict;
				var fallando = 'still_failing' === v.verdict;
				var tipo     = resuelto ? 'ok' : ( fallando ? 'error' : 'warn' );
				var titulo   = resuelto ? '✅ RESOLVED · the finding is closed'
					: ( fallando ? 'Still reproducible · the repair did not eliminate it'
						: 'Applied, but without deterministic confirmation' );

				var pruebas = [];
				if ( false === v.cause_present ) { pruebas.push( 'The root cause is no longer present in the deployed code.' ); }
				if ( true === v.cause_present ) { pruebas.push( 'The root cause IS STILL present in the deployed code.' ); }
				if ( v.recurred ) { pruebas.push( 'The error was logged again after the repair.' ); }
				else { pruebas.push( 'There were no new occurrences of the error after the repair.' ); }
				if ( v.health ) { pruebas.push( v.health_inconclusive ? 'Site check: inconclusive (' + v.health + ').' : 'Site check: ' + v.health ); }

				return consoleSequence( [ [ tipo, titulo, v.message ] ] )
					.then( function () { return usageSummaryLine( 'Cumulative repair usage' ); } )
					.then( function () {
						appendPanelSection(
							'closure',
							'Cierre',
							'<div class="abh-console-section"><span class="abh-console-kicker ' + ( resuelto ? 'is-ok' : ( fallando ? 'is-stop' : 'is-warn' ) ) + '">FINAL VERIFICATION</span>' +
							'<h3>' + esc( titulo ) + '</h3><p>' + esc( v.message ) + '</p>' +
							'<h4>Evidence used</h4>' + listHtml( pruebas ) + '</div>',
							resuelto ? 'is-ok' : ( fallando ? 'is-warning' : 'is-warning' )
						);
						setConsoleState(
							resuelto ? 'Resolved and verified' : ( fallando ? 'Applied but NOT resolved · rollback available' : 'Applied · confirm the original test manually' ),
							resuelto ? 'is-done' : 'is-warning'
						);
						setProgress( 100 );
						setActions( postApplyActions() );
						if ( resuelto ) {
							repair.verified = true;
							resolveIncidentInUi( repair.key );
							document.dispatchEvent( new window.CustomEvent( 'abh:repair-verified', {
								detail: {
									title: titulo,
									message: v.message || '',
									key: repair.key || ''
								}
							} ) );
						}
						if ( repair.$card ) {
							repair.$card.find( '.abh-result' ).html(
								'<p class="' + ( resuelto ? 'abh-msg-ok' : 'abh-msg-warn' ) + '">' + ( resuelto ? '✅ ' : '⚠️ ' ) + esc( v.message ) + '</p>' +
								'<p class="abh-muted">The complete evidence is in HUNTER AI Repair Console.</p>'
							).show();
						}
					} );
			} )
			.fail( function () {
				// La verificación es un extra: si falla, el cambio sigue aplicado
				// y con rollback. Se informa sin fingir un cierre que no hubo.
				return consoleLine( 'warn', 'Automatic verification could not be completed', 'The change is applied and can be rolled back, but the detector could not be rerun. Open the site and repeat the original test to confirm it.' )
					.then( function () {
						setConsoleState( 'Applied · verification pending', 'is-warning' );
						setProgress( 100 );
						setActions( postApplyActions() );
					} );
			} );
	}

	function resetConsole() {
		cancelConsoleMessages();
		var paceChoice = adaptiveConsolePace( repair.mode );
		repair.job = '';
		repair.scanId = '';
		repair.token = '';
		repair.envToken = '';
		repair.path = '';
		repair.sha = '';
		repair.diff = [];
		repair.logs = [];
		repair.result = null;
		repair.closed = false;
		repair.messageQueue = [];
		repair.pace = paceChoice.pace;
		repair.paceAuto = paceChoice.automatic;
		repair.sessionOrdinal = paceChoice.ordinal;
		repair.flushMessages = false;
		repair.wakeMessage = null;
		repair.panelSections = {};
		repair.panelOrder = [];
		repair.environmentType = '';
		repair.reportBusy = false;
		repair.manualGuide = null;
		repair.usage = { in: 0, out: 0 };
		repair.meter = null;
		repair.cost = '';
		repair.uiPaused = false;
		repair.autoScroll = true;
		repair.activeTab = 'analysis';
		repair.startedAt = Date.now();
		repair.firstUsefulAt = 0;
		repair.preliminary = null;
		repair.verified = false;
		$( '#abh-console-manual-guide-inline' ).prop( 'hidden', true ).prop( 'disabled', false ).text( 'What should I do?' );
		$( '#abh-console-terminal' ).empty();
		$( '#abh-console-phase-nav' ).empty();
		$( '#abh-console-phase-history' ).html( '<div class="abh-console-empty"><strong>Preparing the history</strong><p>Analyst, Skeptic, Evidence Collector and Referee will appear here as they finish.</p></div>' );
		resetConsoleSummary();
		$( '#abh-console-job' ).text( 'Creating secure session…' );
		$( '#abh-console-route' ).text( 'Pending identification' );
		$( '#abh-console-fingerprint' ).text( 'Pending' );
		$( '#abh-console-autoscroll' ).prop( 'checked', true );
		// Esta edición no aplica cambios, así que el espejo azul del pie no tiene
		// ninguna acción que reflejar. Se deja oculto en cada reinicio para que
		// una hoja de estilos ajena no lo saque a la vista sin nada detrás.
		$( '#abh-console-aplicar' ).prop( 'hidden', true );
		$( '#abh-console-pause' ).attr( 'aria-pressed', 'false' ).removeClass( 'is-paused' ).find( 'span:last' ).text( 'Pause' );
		$( '#abh-console-pause .dashicons' ).attr( 'class', 'dashicons dashicons-controls-pause' );
		setConsoleView( 'analysis' );
		syncConsoleContext();
		setProgress( 2 );
		setConsoleState( 'No changes applied', 'is-safe' );
		setActions( '<button type="button" class="button" id="abh-console-download-log" disabled>Download log</button><button type="button" class="button" data-console-close>Close</button>' );
		updatePaceLabel();
	}

	function openConsole( $source, mode ) {
		repair.$source = $source;
		repair.$card = $source.closest( '.abh-incident, .abh-card, .abh-motor' );
		repair.key = String( $source.data( 'key' ) || '' );
		repair.mode = mode || 'thoth';
		resetConsole();
		syncConsoleContext();
		$( '#abh-console' ).addClass( 'is-open' ).attr( 'aria-hidden', 'false' );
		$( 'body' ).addClass( 'abh-console-open' );
		window.setTimeout( function () { $( '.abh-console-close' ).trigger( 'focus' ); }, 20 );
	}

	function closeConsole() {
		repair.closed = true;
		cancelConsoleMessages();
		$( '#abh-console' ).removeClass( 'is-open' ).attr( 'aria-hidden', 'true' );
		$( 'body' ).removeClass( 'abh-console-open' );
		if ( repair.$source ) {
			repair.$source.trigger( 'focus' );
		}
	}

	function request( action, data ) {
		// Todo lo que pasa por aquí acaba en una línea roja de la consola vía
		// failConsole() o en el .fail() de quien llamó. El aviso global sería un
		// segundo mensaje por el mismo fallo, así que se reclama la petición.
		return claimFailure( post( action, data ) ).then( function ( res ) {
			var d = res.data || {};
			if ( ! res.success ) {
				return $.Deferred().reject( d ).promise();
			}
			return d;
		}, function () {
			return $.Deferred().reject( { message: ABH.i18n.error } ).promise();
		} );
	}

	function stopIfClosed( $btn ) {
		if ( ! repair.closed ) {
			return false;
		}
		if ( $btn ) {
			done( $btn );
		}
		return true;
	}

	function requestIfConsoleOpen( action, data, $btn ) {
		if ( stopIfClosed( $btn ) ) {
			return $.Deferred().reject( { handled: true } ).promise();
		}
		return request( action, data );
	}

	function failConsole( err ) {
		// Un bloqueo también es «algo concreto delante», pero quien lo decide
		// sigue siendo el servidor: si el fallo ocurrió antes de que exista un
		// trabajo, no hay nada sobre lo que preguntar.
		syncPrompt( err );
		var msg = err && err.message ? err.message : ABH.i18n.error;
		repair.lastFailure = err || {};
		rememberUsage( err );
		// El archivo citado por el registro ya no está: no es un fallo ambiguo
		// de lectura ni una reparación fallida. La comprobación ocurre antes de
		// crear el trabajo y antes de llamar al proveedor, así que se comunica
		// como incidencia antigua y no se ofrecen reintentos inútiles.
		if ( err && err.file_missing ) {
			repair.path = err.rel_path || repair.path;
			syncConsoleContext();
			var missingEvidence = ( err.evidence || [] ).map( function ( item ) {
				return [ 'ok', 'Verified fact', item ];
			} );
			return consoleSequence( [
				[ 'info', 'The file no longer exists', msg ],
				[ 'ok', 'There is nothing to repair at that path', 'The check was local: no AI session was created, no tokens were spent, and no files were modified.' ]
			].concat( missingEvidence ) ).then( function () {
				setProgress( 100 );
				setConsoleState( 'Old incident · the file no longer exists', 'is-safe' );
				setActions(
					'<button type="button" class="button" id="abh-console-download-log">Download log</button>' +
					'<button type="button" class="button" data-console-close>Close</button>'
				);
				if ( repair.$source ) { done( repair.$source ); }
			} );
		}
		// Revisión manual accionable: HUNTER confirmó la causa pero no aplicó cambios
		// dentro del archivo del incidente. No es un fallo del proceso, así que no se
		// pinta en rojo; se muestra en ámbar con la causa raíz y el arreglo sugerido.
		if ( err && err.manual_review ) {
			return consoleLine( 'warn', 'This attempt could not be applied — the analysis remains valid', msg + ' This does not rule out the repair: the diagnosis is preserved and you can apply it manually using the information below, or try again with more evidence.' ).then( function () {
				return usageSummaryLine( 'Review usage' );
			} ).then( function () {
				setConsoleState( 'This attempt did not succeed · nothing was modified and the diagnosis is preserved', 'is-warn' );
				var manualActions = '<button type="button" class="button button-primary" id="abh-console-manual-guide">What should I do?</button>' +
					'<button type="button" class="button" id="abh-console-download-log">Download log</button>';
				// Un caso que no salió es exactamente el que hay que ver del otro
				// lado. El botón aparece aquí, en el momento en que duele: prepara
				// el reporte anonimizado y lo deja listo para descargar.
				manualActions += '<button type="button" class="button" id="abh-console-report">Prepare anonymous report</button>';
				// Cuando lo que falló fue la FORMA de la respuesta, el camino no
				// es recopilar más evidencia —ya está toda— sino volver a pedir
				// el parche. Es el botón que faltaba, y por cuya ausencia esta
				// pantalla era un callejón sin salida.
				if ( err.reformable ) {
					manualActions += '<button type="button" class="button abh-btn-verde" id="abh-console-retry-fix">Retry the repair</button>';
				}
				if ( err.can_retry_evidence ) {
					manualActions += '<button type="button" class="button button-primary" id="abh-console-retry-evidence">Collect more evidence and retry</button>';
				}
				manualActions += '<button type="button" class="button" data-console-close>Close</button>';
				setActions( manualActions );
				setManualGuideInline( true );
				setProgress( 100 );
				requestManualGuide( true );
				if ( repair.$source ) { done( repair.$source ); }
			} );
		}
		var contractIssues = err && Array.isArray( err.contract_issues ) ? err.contract_issues : [];
		var failureLine = consoleLine( 'error', 'The repair was stopped', msg );
		if ( contractIssues.length ) {
			failureLine = failureLine.then( function () {
				return consoleLine(
					'warn',
					'Which part of the contract was invalid',
					contractIssues.join( ' ' )
				);
			} );
		}
		return failureLine.then( function () {
			return usageSummaryLine( 'Usage before stopping' );
		} ).then( function () {
			var contract = err && err.recoverable && err.resume_action === 'thoth_resume_contract';
			setConsoleState(
				contract ? 'Invalid contract · evidence preserved'
					: ( err && err.reformable ? 'The first attempt failed · the analysis remains valid'
					: ( err && err.can_retry_evidence ? 'Candidate blocked · you can investigate again'
					: 'Process stopped · no files were modified' ) ),
				'is-error'
			);
			var actions = '<button type="button" class="button" id="abh-console-download-log">Download log</button>';
			actions += '<button type="button" class="button" id="abh-console-report">Prepare anonymous report</button>';
			// La propuesta caducó o ya se usó: el único camino es volver a
			// analizar, y se ofrece aquí en vez de dejar que se pulse tres veces
			// el mismo botón para leer tres veces el mismo error.
			if ( err && err.reanalizar ) {
				actions += '<button type="button" class="button abh-btn-verde" id="abh-console-reanalizar">Analyze again</button>';
			}
			if ( contract ) {
				actions += '<button type="button" class="button button-primary" id="abh-console-retry-contract">Retry this phase only</button>';
			} else if ( err && err.reformable ) {
				// Primero el que de verdad resuelve este fallo. «Más evidencia»
				// se ofrece detrás, porque aquí no falta evidencia.
				actions += '<button type="button" class="button abh-btn-verde" id="abh-console-retry-fix">Retry the repair</button>';
				if ( err.can_retry_evidence ) {
					actions += '<button type="button" class="button" id="abh-console-retry-evidence">Collect more evidence</button>';
				}
			} else if ( err && err.can_retry_evidence ) {
				actions += '<button type="button" class="button button-primary" id="abh-console-retry-evidence">Collect more evidence and retry</button>';
			}
			actions += '<button type="button" class="button" data-console-close>Close</button>';
			setActions( actions );
			setProgress( 100 );
			if ( repair.$source ) { done( repair.$source ); }
		} );
	}

	function listHtml( items ) {
		if ( ! items || ! items.length ) {
			return '<p class="abh-muted">No additional items were recorded.</p>';
		}
		return '<ul>' + items.map( function ( item ) { return '<li>' + esc( item ) + '</li>'; } ).join( '' ) + '</ul>';
	}

	function panelSectionId( phase ) {
		return 'abh-console-phase-' + String( phase || 'info' ).replace( /[^a-z0-9_-]/gi, '-' );
	}

	function appendPanelSection( phase, label, body, tone ) {
		var id = panelSectionId( phase );
		var $history = $( '#abh-console-phase-history' );
		var $nav = $( '#abh-console-phase-nav' );
		if ( ! $history.length ) { return; }
		$history.find( '.abh-console-empty' ).remove();
		// `phase` puede traer dato del servidor —'evidence-' + data.round— y
		// entraba tal cual en data-phase por concatenación. La ficha se arma como
		// nodo: id, data-phase y el tono se ponen con .attr()/.addClass(). El
		// cuerpo sigue siendo marcado que construye este archivo, no el servidor.
		var $section = $( '<details class="abh-console-phase-card" open></details>' )
			.addClass( String( tone || '' ) )
			.attr( 'id', id )
			.attr( 'data-phase', String( phase === null || phase === undefined ? '' : phase ) );
		$section.append(
			$( '<summary></summary>' )
				.append( $( '<span></span>' ).text( String( label === null || label === undefined ? '' : label ) ) )
				.append( $( '<small></small>' ).text( 'Keep visible' ) )
		);
		$section.append( $( '<div class="abh-console-phase-body"></div>' ).html( body ) );
		if ( repair.panelSections[ phase ] ) {
			$( '#' + id ).replaceWith( $section );
		} else {
			repair.panelSections[ phase ] = true;
			repair.panelOrder.push( phase );
			$history.append( $section );
			$nav.append(
				$( '<button type="button" class="button-link abh-console-phase-link"></button>' )
					.attr( 'data-phase-target', id )
					.text( String( label === null || label === undefined ? '' : label ) )
			);
		}
		$( '#' + id ).addClass( 'is-new' );
		window.setTimeout( function () { $( '#' + id ).removeClass( 'is-new' ); }, 1800 );

		if ( phase === 'diff' || phase === 'verification' || phase === 'closure' || phase === 'environment' ) {
			var planCopy = phase === 'diff'
				? '<p>The change candidate is ready for review. Open Event view to inspect the diff and its complete conditions.</p>'
				: ( phase === 'environment'
					? '<p>A local environment change was prepared. It still requires authorization and post-change verification.</p>'
					: '<p>The ' + esc( label.toLowerCase() ) + ' phase finished. Full details remain in Event view.</p>' );
			updateSummaryCard( 'plan', planCopy, { selector: '#abh-console-plan-state', text: phase === 'verification' || phase === 'closure' ? 'Verified result' : 'Plan prepared' }, tone || '' );
		}
	}

	function renderThothPanel( phase, data ) {
		// Defensa de fondo: ninguna fase debe tumbar la consola por un dato que
		// no llegó. Si falta, se dice; no se lanza.
		if ( ! data || 'object' !== typeof data ) { return; }
		rememberUsage( data );
		var html = '';
		if ( phase === 'analysis' ) {
			var a = data.analysis || {};
			var confidence = Number( a.confidence || data.confidence || 0 );
			if ( confidence > 0 && confidence <= 1 ) { confidence = confidence * 100; }
			html = '<div class="abh-console-section"><span class="abh-console-kicker">ANALYST</span><h3>What appears to be happening</h3>' +
				'<p>' + esc( a.what_happens ) + '</p><h4>Likely cause</h4><p>' + esc( a.root_cause ) + '</p>' +
				'<h4>What must be preserved</h4><p>' + esc( a.behavior_to_preserve ) + '</p><h4>Evidence</h4>' + listHtml( a.evidence ) + '</div>';
			updateSummaryCard( 'hypothesis', '<p>' + esc( a.what_happens || 'The hypothesis does not yet have a complete explanation.' ) + '</p>' + ( a.behavior_to_preserve ? '<p class="abh-console-summary-note"><strong>Preserve:</strong> ' + esc( a.behavior_to_preserve ) + '</p>' : '' ), { selector: '#abh-console-confidence', text: confidence ? 'Confidence: ' + Math.round( confidence ) + '%' : 'Confidence: under review' }, 'is-info' );
			updateSummaryCard( 'cause', '<p>' + esc( a.root_cause || 'The root cause has not yet been confirmed.' ) + '</p>', null, 'is-info' );
			appendPanelSection( 'analysis', 'Analyst', html, 'is-info' );
		} else if ( phase === 'challenge' ) {
			var c = data.challenge || {};
			html = '<div class="abh-console-section"><span class="abh-console-kicker is-warn">SKEPTIC</span><h3>Questions raised</h3>' +
				listHtml( c.challenges ) + '<h4>Alternative explanation</h4><p>' + esc( c.alternative_explanation || 'No strong alternative explanation was found.' ) + '</p>' +
				'<h4>Missing evidence</h4>' + listHtml( c.missing_evidence ) + '</div>';
			updateSummaryCard( 'hypothesis', '<p><strong>Skeptic questions</strong></p>' + summaryList( c.challenges, 3 ) + ( c.alternative_explanation ? '<p class="abh-console-summary-note"><strong>Alternative:</strong> ' + esc( c.alternative_explanation ) + '</p>' : '' ), { selector: '#abh-console-confidence', text: 'Confidence: under review' }, 'is-warning' );
			appendPanelSection( 'challenge', 'Skeptic', html, 'is-warning' );
		} else if ( phase === 'evidence' ) {
			var e = data.evidence || {};
			var defs = ( e.definitions || [] ).map( function ( d ) { return ( d.class ? d.class + '::' : '' ) + d.name + ' — ' + d.visibility + ' — ' + d.file + ':' + d.line; } );
			var calls = ( e.calls || [] ).map( function ( c ) { return ( c.scope ? c.scope + ' → ' : '' ) + ( c.class ? c.class + '::' : '' ) + c.name + ' — ' + c.file + ':' + c.line; } );
			var runtime = e.runtime || {};
			var comparisons = ( runtime.comparisons || [] ).map( function ( c ) { return c.symbol + ': disco=' + c.disk_visibility + ', runtime=' + c.runtime_visibility + ( c.contradiction ? ' · CONTRADICTION' : ' · matches' ); } );
			html = '<div class="abh-console-section"><span class="abh-console-kicker is-ok">EVIDENCE COLLECTOR</span><h3>What was checked directly</h3>' +
				listHtml( e.summary || [] ) + '<h4>Runtime evidence</h4>' + listHtml( runtime.summary || [] ) +
				'<details><summary>View technical inventory</summary><h4>Disk ↔ runtime comparison</h4>' + listHtml( comparisons ) + '<h4>Related definitions</h4>' + listHtml( defs ) + '<h4>Related calls</h4>' + listHtml( calls ) +
				'<h4>Duplicate definitions</h4>' + listHtml( ( e.duplicates || [] ).map( function ( d ) { return d.symbol || 'Duplicate definition'; } ) ) + '</details>' +
				'<p class="abh-muted">Files reviewed: ' + esc( String( e.files_scanned || 0 ) ) + ( e.project_version ? ' · Version: ' + esc( e.project_version ) : '' ) + '</p></div>';
			var evidenceSummary = ( e.summary || [] ).concat( runtime.summary || [] );
			updateSummaryCard( 'evidence', summaryList( evidenceSummary, 4 ) + '<p class="abh-console-summary-note">Files reviewed: ' + esc( String( e.files_scanned || 0 ) ) + '</p>', null, 'is-ok' );
			appendPanelSection( 'evidence-' + String( data.round || 1 ), 'Evidence ' + String( data.round || 1 ), html, 'is-ok' );
		} else if ( phase === 'analysis_enriched' ) {
			var ae = data.analysis || {};
			var enrichedConfidence = Number( ae.confidence || data.confidence || 0 );
			if ( enrichedConfidence > 0 && enrichedConfidence <= 1 ) { enrichedConfidence = enrichedConfidence * 100; }
			html = '<div class="abh-console-section"><span class="abh-console-kicker">ANALYST · EVIDENCE</span><h3>Updated hypothesis</h3><p>' + esc( ae.what_happens ) + '</p><h4>Likely cause</h4><p>' + esc( ae.root_cause ) + '</p><h4>What must be preserved</h4><p>' + esc( ae.behavior_to_preserve ) + '</p><h4>Evidence incorporated</h4>' + listHtml( ae.evidence ) + '</div>';
			updateSummaryCard( 'hypothesis', '<p>' + esc( ae.what_happens || 'Hypothesis updated with the available evidence.' ) + '</p>' + ( ae.behavior_to_preserve ? '<p class="abh-console-summary-note"><strong>Preserve:</strong> ' + esc( ae.behavior_to_preserve ) + '</p>' : '' ), { selector: '#abh-console-confidence', text: enrichedConfidence ? 'Confidence: ' + Math.round( enrichedConfidence ) + '%' : 'Confidence: reviewed' }, 'is-info' );
			updateSummaryCard( 'cause', '<p>' + esc( ae.root_cause || 'The root cause still requires confirmation.' ) + '</p>', null, 'is-info' );
			appendPanelSection( 'analysis-enriched', 'Analyst · evidence', html, 'is-info' );
		} else if ( phase === 'challenge_enriched' ) {
			var ce = data.challenge || {};
			html = '<div class="abh-console-section"><span class="abh-console-kicker is-warn">SKEPTIC · EVIDENCE</span><h3>Questions after reviewing the code</h3>' + listHtml( ce.challenges ) + '<h4>Alternative explanation</h4><p>' + esc( ce.alternative_explanation || 'No strong alternative was found.' ) + '</p><h4>What is still missing</h4>' + listHtml( ce.missing_evidence ) + '</div>';
			updateSummaryCard( 'hypothesis', '<p><strong>Questions after the evidence review</strong></p>' + summaryList( ce.challenges, 3 ) + ( ce.alternative_explanation ? '<p class="abh-console-summary-note"><strong>Alternative:</strong> ' + esc( ce.alternative_explanation ) + '</p>' : '' ), { selector: '#abh-console-confidence', text: 'Confidence: cross-checked' }, 'is-warning' );
			appendPanelSection( 'challenge-enriched', 'Skeptic · evidence', html, 'is-warning' );
		} else if ( phase === 'verdict' ) {
			var v = data.verdict || {};
			var verdictTone = v.repair_allowed ? 'is-ok' : 'is-stop';
			var riskRaw = v.risk || v.severity || '';
			var riskLabel = ( typeof riskRaw === 'string' || typeof riskRaw === 'number' ) && String( riskRaw ) ? String( riskRaw ) : ( v.repair_allowed ? 'Review required' : 'Not authorized' );
			html = '<div class="abh-console-section"><span class="abh-console-kicker ' + ( v.repair_allowed ? 'is-ok' : 'is-stop' ) + '">REFEREE</span>' +
				'<h3>Verdict: ' + esc( String( v.verdict || 'pending' ).replace( /_/g, ' ' ) ) + '</h3><p>' + esc( v.reason ) + '</p>' +
				'<h4>Repair requirements</h4>' + listHtml( v.requirements ) + '<h4>How it must be verified</h4>' + listHtml( v.verification ) + '</div>';
			updateSummaryCard( 'plan', summaryList( v.requirements, 4 ) + ( v.verification && v.verification.length ? '<p class="abh-console-summary-note"><strong>Verification:</strong> ' + esc( v.verification[ 0 ] ) + '</p>' : '' ), { selector: '#abh-console-plan-state', text: v.repair_allowed ? 'Plan allowed in DRY-RUN' : 'Plan blocked' }, verdictTone );
			updateSummaryCard( 'risk', '<p>' + esc( v.reason || 'The Referee did not return a risk explanation.' ) + '</p><p class="abh-console-summary-note"><strong>Verdict:</strong> ' + esc( String( v.verdict || 'pending' ).replace( /_/g, ' ' ) ) + '</p>', { selector: '#abh-console-risk-state', text: String( riskLabel ) }, verdictTone );
			appendPanelSection( 'verdict', 'Referee', html, verdictTone );
		}
	}


	function renderScanPanel( report ) {
		var findings = report && report.findings ? report.findings : [];
		var skipped = report && report.skipped ? report.skipped : [];
		var status = findings.length ? 'is-warn' : 'is-ok';
		var title = findings.length ? 'Files that PHP cannot parse were found' : 'No syntax errors were found';
		var html = '<div class="abh-console-section"><span class="abh-console-kicker ' + status + '">FILE SCAN</span>' +
			'<h3>' + esc( title ) + '</h3>' +
			'<p><strong>' + esc( String( report.scanned || 0 ) ) + '</strong> files reviewed · <strong>' + esc( String( findings.length ) ) + '</strong> error(s) found.</p>';
		if ( findings.length ) {
			html += '<h4>Affected files</h4><ul>' + findings.slice( 0, 30 ).map( function ( f ) {
				return '<li><code>' + esc( f.rel_path + ( f.line ? ':' + f.line : '' ) ) + '</code><br>' + esc( f.short || f.message || 'Syntax error' ) + '</li>';
			} ).join( '' ) + '</ul>';
		}
		if ( skipped.length ) {
			html += '<p class="abh-muted">' + esc( String( skipped.length ) ) + ' file(s) could not be reviewed because of size or permissions. The report saved their relative paths.</p>';
		}
		html += '</div>';
		updateSummaryCard( 'evidence', findings.length ? '<p><strong>' + esc( String( findings.length ) ) + ' syntax finding(s)</strong></p>' + summaryList( findings.slice( 0, 4 ).map( function ( f ) { return f.rel_path + ( f.line ? ':' + f.line : '' ) + ' — ' + ( f.short || f.message || 'Syntax error' ); } ), 4 ) : '<p>No syntax errors were found in the reviewed scope.</p>', null, status );
		updateSummaryCard( 'risk', findings.length ? '<p>One or more files cannot be parsed by PHP. The impact depends on when WordPress attempts to load them.</p>' : '<p>The syntax scan completed cleanly. This does not rule out logic or security problems.</p>', { selector: '#abh-console-risk-state', text: findings.length ? 'Review needed' : 'No syntax risk' }, status );
		appendPanelSection( 'scan', 'Scan', html, status );
	}

	function processSyntaxScan( $btn, nextNotice ) {
		return requestIfConsoleOpen( 'syntax_scan_step', { scan_id: repair.scanId }, $btn ).then( function ( d ) {
			if ( d.done ) {
				var report = d.report || { findings: [], scanned: 0, skipped: [] };
				var found = report.findings ? report.findings.length : 0;
				renderScanPanel( report );
				return consoleSequence( [
					[ found ? 'warn' : 'ok', found ? 'Scan completed with findings' : 'Scan completed with no syntax errors', ( report.scanned || 0 ) + ' files were reviewed without executing them.' ],
					[ 'info', 'Results saved', found ? 'Reload the diagnosis to view each file and decide whether HUNTER AI can repair it or whether it belongs to protected core.' : 'The PHP log will continue to appear separately because it detects errors that occur during normal site use.' ]
				] ).then( function () {
					setProgress( 100 );
					setConsoleState( found ? 'Full scan · review needed' : 'Full scan · valid syntax', found ? 'is-warning' : 'is-done' );
					setActions( '<button type="button" class="button" id="abh-console-download-log">Download log</button><button type="button" class="button button-primary" id="abh-console-view-scan">Ver resultados</button>' );
					done( $btn );
				} );
			}

			setProgress( Math.max( 8, d.progress || 0 ) );
			setConsoleState( 'Scanning files · ' + ( d.scanned || 0 ) + ' reviewed', 'is-working' );
			if ( ( d.progress || 0 ) >= nextNotice ) {
				return consoleLine( 'work', 'Scan at ' + d.progress + '%', 'Reviewed ' + ( d.scanned || 0 ) + ' files. Found ' + ( d.found || 0 ) + ' syntax error(s).' ).then( function () {
					return processSyntaxScan( $btn, nextNotice + 20 );
				} );
			}
			return processSyntaxScan( $btn, nextNotice );
		} );
	}

	function runSyntaxScan( $btn ) {
		var scope = String( $btn.data( 'scope' ) || 'quick' );
		openConsole( $btn, 'scan' );
		busy( $btn, 'Preparing scan…' );
		$( '#abh-console-job' ).text( 'HUNTER AI · file scan' );
		syncConsoleContext();
		setProgress( 3 );
		consoleSequence( [
			[ 'ai', 'I will review the PHP files without executing them', 'This process is separate from debug.log: it looks for damaged files even when the error has not yet been logged.' ],
			[ 'work', scope === 'full' ? 'Preparing full scan' : 'Preparing quick scan', scope === 'full' ? 'The scan will include the root, plugins, themes, mu-plugins, wp-admin, and wp-includes.' : 'The scan will include PHP files in the WordPress root, plugins, themes, and mu-plugins, without treating specific names as special rules.' ]
		] )
			.then( function () { return requestIfConsoleOpen( 'syntax_scan_start', { scope: scope }, $btn ); } )
			.then( function ( d ) {
				repair.scanId = d.scan_id;
				repair.job = d.scan_id;
				$( '#abh-console-job' ).text( d.scan_id + ' · ' + ( scope === 'full' ? 'full' : 'quick' ) );
				return consoleLine( 'ok', 'File map frozen', 'Found ' + d.total + ' candidate files. They will be reviewed in batches to avoid overloading the server.' );
			} )
			.then( function () { return processSyntaxScan( $btn, 20 ); } )
			.fail( function ( err ) {
				if ( err && err.handled ) { return; }
				failConsole( err );
			} );
	}

	function runThoth( $btn ) {
		openConsole( $btn, 'thoth' );
		busy( $btn, 'HUNTER AI is working…' );
		setProgress( 8 );

		var startRequest = requestIfConsoleOpen( 'thoth_start', { key: repair.key }, $btn );
		consoleSequence( [
			[ 'ai', 'Hello. I am HUNTER AI.', 'I will review this error step by step. First I will observe it; then I will challenge my own theory to find the right solution. I will not modify anything without asking for permission.' ],
			[ 'info', 'Engine version', 'AI Bug Hunter v' + ( ABH.version || 'unknown' ) + '. This number identifies the exact build currently running.' ],
			[ 'info', 'How this review works', 'The evidence is analyzed: code structure, affected lines, and common problems. It is then presented to a panel that reviews the code context and proposes the most logical change.' ],
			[ 'work', 'Reading the incident', 'I am locating the file and checking that it is within the allowed area.' ]
		] );
		startRequest
			.then( function ( d ) {
				if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
				repair.job = d.job_id;
				repair.path = d.rel_path;
				repair.sha = d.sha_before;
				$( '#abh-console-job' ).text( d.job_id + ' · ' + d.rel_path );
				syncConsoleContext();
				setProgress( 18 );
				renderLocalPreliminary( d.local_preliminary );
				consoleSequence( [
					[ 'ok', 'Build frozen. Continuing with the scan.', d.explanation, 'SHA-256: ' + d.sha_before ],
					[ 'motor', 'Selected engine', 'API keys are never shown in this console.', d.model_label || 'the configured provider' ],
					[ 'motor', 'Local reading available', d.local_preliminary ? d.local_preliminary.summary : 'Hunter has classified the log entry and will continue checking it.' ],
					[ 'info', 'What does the fingerprint mean?', 'It is the exact identity of the file at this moment. If it changes while you decide, HUNTER AI cancels the repair to avoid overwriting a newer version.' ],
					[ 'work', 'Testing the local engine', 'First I will try to demonstrate an exact solution without consulting Mistral. If that is not enough, I will expand the evidence.' ]
				] );
				return requestIfConsoleOpen( 'thoth_local_triage', { job: repair.job }, $btn )
					.then( function ( local ) {
						if ( local && local.deterministic ) {
							return local;
						}
						consoleLine( 'info', 'The local path needs context', local.message || 'The review will continue with expanded evidence and the configured provider.' );
						consoleLine( 'work', 'Collecting evidence from the deployed code', 'Before asking anything, I inspect the real code: definitions, calls, version, and hashes.' );
						return requestIfConsoleOpen( 'thoth_collect_evidence', { job: repair.job }, $btn )
							.then(
								function ( ev ) {
									repair.evidenceFirst = true;
									renderThothPanel( 'evidence', ev );
									setProgress( 26 );
									consoleSequence( [
										[ 'ok', 'Evidence collected', 'An analyst is consulted with that evidence already available.' ],
										[ 'work', 'Analyzing the underlying cause', 'I now separate the visible error from the real reason, using the available evidence. This phase does not generate code.' ]
									] );
									return requestIfConsoleOpen( 'thoth_analyze', { job: repair.job }, $btn );
								},
								function () {
									repair.evidenceFirst = false;
									consoleSequence( [
										[ 'info', 'No prior evidence', 'The deployed code could not be inspected in this installation, so the classic analysis will continue. This is not an error; one additional round will be needed.' ],
										[ 'work', 'Analyzing the underlying cause', 'I now separate the visible error from the real reason it occurred. This phase does not generate code.' ]
									] );
									return requestIfConsoleOpen( 'thoth_analyze', { job: repair.job }, $btn );
								}
							);
					} );
			} )
			.then( function ( d ) {
				if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
				// El motor determinista ya resolvió el caso sin llamar a la IA:
				// se salta el resto del pipeline y se muestra el diff directo.
				// El archivo señalado está intacto: matches con su original
				// publicado y compila. No hay reparación que proponer, y
				// mandarlo al modelo sería gastar tokens en un archivo sano.
				// Esta vía también corta la cadena: no hay diff que aprobar.
				if ( d && d.nothing_to_repair ) {
					var pruebas = ( d.evidence || [] ).map( function ( h ) {
						return [ 'ok', 'Verified fact', h ];
					} );
					consoleSequence( [
						[ 'ok', 'No safe file change is justified', d.message || '' ]
					].concat( pruebas ) );
					// Toda vía terminal tiene que soltar el botón y dejar
					// acciones. La narración puede seguir poniéndose al día.
					setProgress( 100 );
					setConsoleState( 'Published original verified · no modification proposed', 'is-safe' );
					setActions(
						'<button type="button" class="button" id="abh-console-download-log">Download log</button>' +
						'<button type="button" class="button" data-console-close>Close</button>'
					);
					done( $btn );
					return $.Deferred().reject( { handled: true } ).promise();
				}
				if ( d && d.deterministic ) {
					setProgress( 70 );
					// Los hechos los pone el motor que resolvió, no este archivo.
					// Había un texto fijo aquí que describía siempre el motor de
					// typos: cuando ganaba otro, la consola afirmaba algo falso.
					var hechos = ( d.thoth && d.thoth.analysis && d.thoth.analysis.evidence ) || [];
					var lineas = [ [ 'ok', 'Resolved by the local engine', d.message ] ];
					if ( hechos.length ) {
						lineas.push( [ 'info', 'Why AI was not needed', 'These facts are checked by the machine, not interpreted by anyone:' ] );
						hechos.forEach( function ( h ) { lineas.push( [ 'ok', 'Verified fact', h ] ); } );
					}
					consoleSequence( lineas );
					showDiffReady( d, $btn );
					// La vía determinista termina aquí. Sin este corte, el
					// siguiente eslabón de la cadena corría con undefined y
					// reventaba al pintar el panel del Skeptic, que en esta
					// vía no existe porque nunca se llamó al modelo.
					return $.Deferred().reject( { handled: true } ).promise();
				}
				renderThothPanel( 'analysis', d );
				setProgress( 36 );
				consoleSequence( [
					[ 'ai', 'First explanation ready', d.analysis.what_happens ],
					[ 'info', 'Likely cause', d.analysis.root_cause ],
					[ 'work', 'Challenging the first analysis', 'An independent review looks for false positives, existing safeguards, and plausible alternative explanations.' ]
				] );
				return requestIfConsoleOpen( 'thoth_challenge', { job: repair.job }, $btn );
			} )
			.then( function ( d ) {
				if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
				renderThothPanel( 'challenge', d );
				setProgress( 52 );
				var lines = [ [ 'ai', 'Critical review completed', d.message ] ];
				if ( d.challenge && d.challenge.challenges && d.challenge.challenges.length ) {
					lines.push( [ 'warn', 'The first response was not accepted blindly', d.challenge.challenges[ 0 ] ] );
				}
				// Con la evidencia recogida de entrada, el Analyst y el Skeptic ya
				// trabajaron sobre hechos: repetir la pareja sería pagar dos veces
				// por lo mismo. Se va directo al árbitro.
				if ( repair.evidenceFirst ) {
					lines.push( [ 'ok', 'Second round not needed', 'The Analyst and Skeptic already worked with the code evidence, so their work does not need to be repeated. This saves two model requests in this review.' ] );
					lines.push( [ 'work', 'The Referee is comparing all evidence', 'The Referee will receive the hypothesis, objections, and deterministic code inventory.' ] );
					consoleSequence( lines );
					setProgress( 70 );
					return requestIfConsoleOpen( 'thoth_adjudicate', { job: repair.job }, $btn );
				}
				lines.push( [ 'work', 'Looking for missing evidence', 'Before consulting the Referee, I will review definitions, calls, visibility, versions, hashes, and possible duplicates directly in the deployed code.' ] );
				consoleSequence( lines );
				return requestIfConsoleOpen( 'thoth_collect_evidence', { job: repair.job }, $btn )
					.then( function ( d2 ) {
						if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
						renderThothPanel( 'evidence', d2 );
						setProgress( 58 );
						consoleSequence( [
							[ 'ok', 'Code evidence collected', d2.message ],
							[ 'work', 'Updating the explanation', 'The Analyst will check whether the first hypothesis remains valid after reviewing the actual declarations and calls.' ]
						] );
						return requestIfConsoleOpen( 'thoth_reanalyze', { job: repair.job }, $btn );
					} )
					.then( function ( d3 ) {
						if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
						renderThothPanel( 'analysis_enriched', d3 );
						setProgress( 64 );
						consoleSequence( [
							[ 'ai', 'Hypothesis updated with evidence', d3.analysis.what_happens ],
							[ 'work', 'Repeating the critical review', 'The Skeptic will check whether a reasonable alternative explanation still exists.' ]
						] );
						return requestIfConsoleOpen( 'thoth_rechallenge', { job: repair.job }, $btn );
					} )
					.then( function ( d4 ) {
						if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
						renderThothPanel( 'challenge_enriched', d4 );
						setProgress( 70 );
						consoleSequence( [
							[ 'ai', 'Second critical review completed', d4.message ],
							[ 'work', 'The Referee is comparing all evidence', 'The Referee will receive the updated hypothesis, objections, and deterministic code inventory.' ]
						] );
						return requestIfConsoleOpen( 'thoth_adjudicate', { job: repair.job }, $btn );
					} );
			} )
			.then( function ( d ) {
				if ( stopIfClosed( $btn ) ) { return $.Deferred().reject( { handled: true } ).promise(); }
				renderThothPanel( 'verdict', d );
				if ( ! d.can_prepare_fix ) {
					return consoleLine( 'warn', 'HUMAN REVIEW AND AUTHORIZATION REQUIRED', d.verdict.reason ).then( function () {
						return usageSummaryLine( 'Cumulative review usage' );
					} ).then( function () {
						setProgress( 100 );
						setConsoleState( 'Diagnosis ready · manual guide available · nothing was modified', 'is-safe' );
						var actions = '<button type="button" class="button" id="abh-console-download-log">Download log</button>';
						setManualGuideInline( true );
						actions += '<button type="button" class="button button-primary" id="abh-console-manual-guide">What should I do?</button>';
						actions += '<button type="button" class="button" data-console-close>Close</button>';
						setActions( actions );
						requestManualGuide( true );
						done( $btn );
						return $.Deferred().reject( { handled: true } ).promise();
					} );
				}
				setProgress( 66 );
				consoleSequence( [
					[ 'ok', 'Finding confirmed', d.verdict.reason ],
					[ 'work', 'Preparing the minimal change', 'HUNTER AI Fixer will receive the Referee requirements. The safety gate and linter will then review the result.' ]
				] );
				return requestIfConsoleOpen( 'thoth_prepare_fix', { job: repair.job }, $btn );
			} )
			.then( function ( d ) {
				if ( stopIfClosed( $btn ) ) { return; }
				return showDiffReady( d, $btn );
			} )
			.fail( function ( err ) {
				if ( err && err.handled ) { return; }
				failConsole( err );
			} );
	}

	function diffText() {
		var out = [];
		out.push( '# HUNTER AI Repair Console' );
		out.push( '# Job: ' + ( repair.job || 'no-id' ) );
		out.push( '# File: ' + repair.path );
		out.push( '# Original SHA-256: ' + repair.sha );
		out.push( '--- a/' + repair.path );
		out.push( '+++ b/' + repair.path );
		repair.diff.forEach( function ( r ) {
			if ( r.type === 'gap' ) {
				out.push( '@@ ' + r.text + ' @@' );
			} else {
				out.push( ( r.type === 'add' ? '+' : ( r.type === 'del' ? '-' : ' ' ) ) + r.text );
			}
		} );
		return out.join( '\n' ) + '\n';
	}

	function download( filename, content, mime ) {
		var blob = new Blob( [ content ], { type: mime || 'text/plain;charset=utf-8' } );
		var url = URL.createObjectURL( blob );
		var a = document.createElement( 'a' );
		a.href = url;
		a.download = filename;
		document.body.appendChild( a );
		a.click();
		document.body.removeChild( a );
		URL.revokeObjectURL( url );
	}


	function downloadBase64( filename, base64, mime ) {
		var binary = window.atob( base64 || '' );
		var bytes = new Uint8Array( binary.length );
		for ( var i = 0; i < binary.length; i++ ) {
			bytes[ i ] = binary.charCodeAt( i );
		}
		var blob = new Blob( [ bytes ], { type: mime || 'application/octet-stream' } );
		var url = URL.createObjectURL( blob );
		var a = document.createElement( 'a' );
		a.href = url;
		a.download = filename;
		document.body.appendChild( a );
		a.click();
		document.body.removeChild( a );
		window.setTimeout( function () { URL.revokeObjectURL( url ); }, 1000 );
	}

	function exportReport( openInNewTab ) {
		if ( repair.reportBusy || ! repair.job ) { return; }
		repair.reportBusy = true;
		var popup = openInNewTab ? window.open( 'about:blank', '_blank' ) : null;
		if ( popup ) {
			popup.document.write( '<p style="font-family:system-ui;padding:24px">Preparing HUNTER AI report…</p>' );
		}
		request( 'export_report', {
			job: repair.job,
			events: JSON.stringify( repair.logs ),
			include_diff: '1'
		} ).then( function ( d ) {
			var binary = window.atob( d.base64 || '' );
			var bytes = new Uint8Array( binary.length );
			for ( var i = 0; i < binary.length; i++ ) { bytes[ i ] = binary.charCodeAt( i ); }
			var blob = new Blob( [ bytes ], { type: d.mime || 'text/html;charset=utf-8' } );
			var url = URL.createObjectURL( blob );
			if ( popup ) {
				popup.location = url;
				window.setTimeout( function () { URL.revokeObjectURL( url ); }, 60000 );
			} else {
				var a = document.createElement( 'a' );
				a.href = url;
				a.download = d.filename || 'HUNTER-AI-report.html';
				document.body.appendChild( a );
				a.click();
				document.body.removeChild( a );
				window.setTimeout( function () { URL.revokeObjectURL( url ); }, 1000 );
			}
		} ).fail( function ( err ) {
			if ( popup ) { popup.close(); }
			consoleLine( 'error', 'The report could not be generated', err && err.message ? err.message : ABH.i18n.error );
		} ).always( function () { repair.reportBusy = false; } );
	}


	function finishRecoveredVerdict( verdict ) {
		renderThothPanel( 'verdict', verdict );
		if ( verdict.can_prepare_fix ) {
			return consoleLine( 'ok', 'Finding confirmed', verdict.verdict.reason )
				.then( function () { return requestIfConsoleOpen( 'thoth_prepare_fix', { job: repair.job }, repair.$source ); } )
				.then( function ( fix ) { return showDiffReady( fix, repair.$source ); } );
		}
		return consoleLine( 'warn', 'The review ended without automatic repair', verdict.verdict.reason )
			.then( function () { return usageSummaryLine( 'Cumulative review usage' ); } )
			.then( function () {
				setProgress( 100 );
				setConsoleState( 'Review completed · nothing was modified', 'is-warning' );
				var actions = '<button type="button" class="button" id="abh-console-download-log">Download log</button>';
				setManualGuideInline( true );
				setActions( actions + '<button type="button" class="button button-primary" id="abh-console-manual-guide">What should I do?</button><button type="button" class="button" data-console-close>Close</button>' );
				requestManualGuide( true );
			} );
	}

	function continueRecoveredPhase( phase, d ) {
		rememberUsage( d );
		if ( phase === 'analyze' ) {
			renderThothPanel( 'analysis', d );
			return consoleLine( 'ok', 'Analyst contract recovered', 'I will continue from the critical review without repeating the build freeze.' )
				.then( function () { return requestIfConsoleOpen( 'thoth_challenge', { job: repair.job }, repair.$source ); } )
				.then( function ( next ) { return continueRecoveredPhase( 'challenge', next ); } );
		}
		if ( phase === 'challenge' ) {
			renderThothPanel( 'challenge', d );
			return consoleLine( 'ok', 'Skeptic contract recovered', 'I will now collect the requested deterministic evidence.' )
				.then( function () { return requestIfConsoleOpen( 'thoth_collect_evidence', { job: repair.job }, repair.$source ); } )
				.then( function ( evidence ) {
					renderThothPanel( 'evidence', evidence );
					return requestIfConsoleOpen( 'thoth_reanalyze', { job: repair.job }, repair.$source );
				} )
				.then( function ( next ) { return continueRecoveredPhase( 'reanalyze', next ); } );
		}
		if ( phase === 'reanalyze' ) {
			renderThothPanel( 'analysis_enriched', d );
			return consoleLine( 'ok', 'Evidence-backed Analyst contract recovered', 'I will continue only with the second critical review.' )
				.then( function () { return requestIfConsoleOpen( 'thoth_rechallenge', { job: repair.job }, repair.$source ); } )
				.then( function ( next ) { return continueRecoveredPhase( 'rechallenge', next ); } );
		}
		if ( phase === 'rechallenge' ) {
			renderThothPanel( 'challenge_enriched', d );
			return consoleLine( 'ok', 'Second review contract recovered', 'The previous evidence remains intact. I will continue with the Referee.' )
				.then( function () { return requestIfConsoleOpen( 'thoth_adjudicate', { job: repair.job }, repair.$source ); } )
				.then( function ( next ) { return continueRecoveredPhase( 'adjudicate', next ); } );
		}
		if ( phase === 'adjudicate' ) {
			return finishRecoveredVerdict( d );
		}
		return $.Deferred().reject( { message: 'The recovered phase has no registered continuation.' } ).promise();
	}

	function retryContractPhase() {
		// Un botón deshabilitado ocupa el sitio para que la barra no parpadee
		// mientras se rehace la fase. Ya no lleva el id de aprobación: en esta
		// edición showDiffReady no lo sustituye por ninguna acción de aplicar, y
		// dejarlo marcado hacía que el espejo azul del pie prometiera una.
		setActions( '<button type="button" class="button" disabled>Preparing the diagnosis…</button>' );
		setConsoleState( 'Resuming only the failed phase', 'is-working' );
		setProgress( 72 );
		var phase = repair.lastFailure && repair.lastFailure.phase ? repair.lastFailure.phase : '';
		consoleSequence( [
			[ 'info', 'The previous evidence is preserved', 'I will not repeat the freeze, scan, or completed phases. Only the failed contract will be requested again.' ],
			[ 'work', 'Retrying the contract', 'I will first try to normalize it and, if necessary, request a format correction without repeating the analysis.' ]
		] ).then( function () {
			return requestIfConsoleOpen( 'thoth_resume_contract', { job: repair.job }, repair.$source );
		} ).then( function ( d ) {
			return continueRecoveredPhase( phase, d );
		} ).fail( function ( err ) { if ( err && err.handled ) { return; } failConsole( err ); } );
	}

	function retryEvidenceRound() {
		setActions( '<button type="button" class="button" disabled>Collecting evidence…</button>' );
		setConsoleState( 'New evidence round', 'is-working' );
		setProgress( 42 );
		consoleSequence( [
			[ 'warn', 'The first proposal was blocked', 'No changes were made. I will reopen the analysis without weakening the safety gate.' ],
			[ 'work', 'Looking for additional evidence', 'I will recheck definitions, calls, versions, duplicates, and hashes before requesting another patch.' ]
		] )
			.then( function () { return requestIfConsoleOpen( 'thoth_collect_evidence', { job: repair.job }, repair.$source ); } )
			.then( function ( d ) { renderThothPanel( 'evidence', d ); return requestIfConsoleOpen( 'thoth_reanalyze', { job: repair.job }, repair.$source ); } )
			.then( function ( d ) { renderThothPanel( 'analysis_enriched', d ); return requestIfConsoleOpen( 'thoth_rechallenge', { job: repair.job }, repair.$source ); } )
			.then( function ( d ) { renderThothPanel( 'challenge_enriched', d ); return requestIfConsoleOpen( 'thoth_adjudicate', { job: repair.job }, repair.$source ); } )
			.then( function ( d ) {
				renderThothPanel( 'verdict', d );
				if ( d.can_prepare_fix ) {
					return consoleLine( 'ok', 'The new evidence confirmed the finding', d.verdict.reason )
						.then( function () { return requestIfConsoleOpen( 'thoth_prepare_fix', { job: repair.job }, repair.$source ); } )
						.then( function ( fix ) { return showDiffReady( fix, repair.$source ); } );
				}
				return consoleLine( 'warn', 'The cause still needs supervision', d.verdict.reason ).then( function () {
					return usageSummaryLine( 'Cumulative review usage' );
				} ).then( function () {
					setProgress( 100 );
					var actions = '<button type="button" class="button" id="abh-console-download-log">Download log</button>';
					setManualGuideInline( true );
					actions += '<button type="button" class="button button-primary" id="abh-console-manual-guide">What should I do?</button>';
					actions += '<button type="button" class="button" data-console-close>Close</button>';
					setActions( actions );
					setConsoleState( 'Review updated · nothing was modified', 'is-warning' );
					requestManualGuide( true );
				} );
			} )
			.fail( function ( err ) { if ( err && err.handled ) { return; } failConsole( err ); } );
	}

	function guideList( items, ordered ) {
		items = Array.isArray( items ) ? items.filter( function ( item ) { return String( item || '' ).trim(); } ) : [];
		if ( ! items.length ) { return ''; }
		var tag = ordered ? 'ol' : 'ul';
		return '<' + tag + '>' + items.map( function ( item ) { return '<li>' + esc( item ) + '</li>'; } ).join( '' ) + '</' + tag + '>';
	}

	function hasUsableDiff( rows ) {
		return Array.isArray( rows ) && rows.some( function ( row ) {
			return row && ( row.type === 'add' || row.type === 'del' );
		} );
	}

	function manualGuideText( guide ) {
		var diffAvailable = !! guide.has_diff;
		var out = [
			'AI Bug Hunter — Repair help',
			'Job: ' + ( guide.job_id || repair.job || 'no-id' ),
			'File: ' + ( guide.rel_path || repair.path || 'not identified' ) + ( guide.line ? ':' + guide.line : '' ),
			'',
			'WHAT THIS MEANS',
			diffAvailable
				? 'AI Bug Hunter found a specific proposed change. Nothing was installed or modified.'
				: 'AI Bug Hunter found useful clues, but it could not prove one exact repair safely. Nothing was modified.',
			'',
			'WHAT TO DO NOW',
			diffAvailable
				? '1. If you are not comfortable editing website files, send this guide and the separate diff to your hosting support or developer.\n2. If you manage the site yourself, create a backup and test the change on staging first.\n3. Repeat the action that caused the error after the repair.'
				: '1. Send this guide to your hosting support or developer.\n2. Ask them to confirm the missing evidence below.\n3. Do not edit PHP, JavaScript, or CSS until an exact repair is verified.',
			'',
			'MESSAGE FOR SUPPORT',
			diffAvailable
				? 'Please review this AI Bug Hunter guide and the separate diff on staging. Confirm the installed plugin version, make a backup, and test the original error before changing production.'
				: 'Please review this AI Bug Hunter guide. No reliable diff was generated. Confirm the installed plugin version and missing evidence before proposing or making any code change.',
			'',
			'TECHNICAL DETAILS',
			'',
			'DIAGNOSIS',
			guide.diagnosis || guide.verdict_reason || 'Review the analysis report.',
			'',
			'ROOT CAUSE',
			guide.root_cause || 'The cause was not fully demonstrated.'
		];
		function addSection( title, items ) {
			if ( ! Array.isArray( items ) || ! items.length ) { return; }
			out.push( '', title );
			items.forEach( function ( item, index ) { out.push( ( index + 1 ) + '. ' + item ); } );
		}
		addSection( 'MISSING EVIDENCE', guide.missing_evidence );
		addSection( 'SAFE PROCEDURE', guide.steps );
		addSection( 'VERIFICATION', guide.verification );
		if ( Array.isArray( guide.proposals ) && guide.proposals.length ) {
			out.push( '', 'PROPOSALS TO REVIEW (NOT COMMANDS)' );
			guide.proposals.forEach( function ( proposal ) { out.push( '- ' + ( proposal.autor || 'Reviewer' ) + ': ' + ( proposal.propuesta || '' ) ); } );
		}
		out.push( '', guide.has_diff ? 'A diff is available separately.' : 'No reliable diff was generated. Do not invent values: retrieve the canonical file or the specified evidence.' );
		return out.join( '\n' ) + '\n';
	}

	function openManualGuide( guide ) {
		guide = guide || {};
		guide.has_diff = !! ( guide.has_diff && hasUsableDiff( repair.diff ) );
		repair.manualGuide = guide;
		var location = esc( guide.rel_path || repair.path || 'Unidentified file' ) + ( guide.line ? ':' + esc( guide.line ) : '' );
		var status = guide.has_diff
			? '<div class="abh-manual-guide-status is-ready"><strong>An exact proposal is ready</strong><span>Your site was not changed. A technical person can review the proposed lines before making the repair.</span></div>'
			: '<div class="abh-manual-guide-status is-caution"><strong>No exact repair was proven</strong><span>Your site was not changed. Do not edit files by guessing; use the next steps below.</span></div>';
		var proposals = Array.isArray( guide.proposals ) ? guide.proposals.map( function ( proposal ) {
			return '<article><strong>' + esc( proposal.autor || 'Reviewer' ) + '</strong><p>' + esc( proposal.propuesta || '' ) + '</p></article>';
		} ).join( '' ) : '';
		var plainSummary = guide.has_diff
			? 'AI Bug Hunter found a specific change that may solve this problem. It has only prepared the change for review; nothing has been installed or modified.'
			: 'AI Bug Hunter found useful clues, but it could not prove one exact change safely. More information is needed before anyone edits the site.';
		var nextSteps = guide.has_diff
			? '<ol><li><strong>If you are not comfortable editing website files:</strong> download this guide and the diff, then send both to your hosting support or developer.</li><li><strong>If you manage the site yourself:</strong> create a backup, test the change on a staging copy, and use the technical details below.</li><li>After the repair, repeat the action that caused the error and confirm the rest of the site still works.</li></ol>'
			: '<ol><li>Download this guide and send it to your hosting support or developer.</li><li>Ask them to confirm the missing evidence listed in the technical details.</li><li>Do not change PHP, JavaScript, or CSS until an exact repair has been verified.</li></ol>';
		var helpRequest = guide.has_diff
			? 'Please review the attached AI Bug Hunter guide and diff on a staging copy. Confirm that the proposed change matches the installed plugin version, make a backup, and test the original error before changing production.'
			: 'Please review the attached AI Bug Hunter guide. No reliable diff was generated. Confirm the installed plugin version and the missing evidence before proposing or making any code change.';
		var technical =
			'<details class="abh-manual-guide-technical"><summary>Technical details for a developer</summary><div>' +
			'<div class="abh-manual-guide-location"><span>TARGET FILE</span><code>' + location + '</code></div>' +
			'<section><h3>What happened</h3><p>' + esc( guide.diagnosis || guide.error_text || 'Review the analysis report.' ) + '</p></section>' +
			'<section><h3>Root cause</h3><p>' + esc( guide.root_cause || guide.verdict_reason || 'The cause was not fully demonstrated.' ) + '</p></section>' +
			( guide.failure_message ? '<section class="is-warning"><h3>Why there is no automatic repair</h3><p>' + esc( guide.failure_message ) + '</p></section>' : '' ) +
			( guide.missing_evidence && guide.missing_evidence.length ? '<section class="is-warning"><h3>Evidence to confirm</h3>' + guideList( guide.missing_evidence, false ) + '</section>' : '' ) +
			( proposals ? '<section><h3>Proposals to review</h3><p class="abh-manual-guide-note">These are guidance, not commands. Do not copy values that are not demonstrated by the canonical version of the affected plugin.</p><div class="abh-manual-guide-proposals">' + proposals + '</div></section>' : '' ) +
			'<section><h3>Safe procedure</h3>' + guideList( guide.steps, true ) + '</section>' +
			( guide.verification && guide.verification.length ? '<section><h3>How to verify the repair</h3>' + guideList( guide.verification, false ) + '</section>' : '' ) +
			( guide.behavior_to_preserve ? '<section><h3>Behavior that must be preserved</h3><p>' + esc( guide.behavior_to_preserve ) + '</p></section>' : '' ) +
			( guide.has_diff ? '<section><h3>Proposed diff</h3><p class="abh-manual-guide-note">This diff is for review and manual application. AI Bug Hunter will not apply it.</p>' + renderDiff( repair.diff ) + '</section>' : '' ) +
			'</div></details>';
		var html = status +
			'<section class="abh-manual-guide-simple"><span class="abh-manual-guide-step">1</span><div><h3>What this means</h3><p>' + plainSummary + '</p></div></section>' +
			'<section class="abh-manual-guide-simple"><span class="abh-manual-guide-step">2</span><div><h3>What you should do now</h3>' + nextSteps + '</div></section>' +
			'<section class="abh-manual-guide-support"><h3>Message for your hosting support or developer</h3><p>' + esc( helpRequest ) + '</p><p class="abh-manual-guide-note">Use “Download guide” below and attach the file to your support request.' + ( guide.has_diff ? ' Attach the downloaded diff too.' : '' ) + '</p></section>' +
			technical;
		$( '#abh-manual-guide-body' ).html( html );
		$( '#abh-manual-guide-download-diff' ).prop( 'hidden', ! guide.has_diff );
		$( '#abh-manual-guide-modal' ).prop( 'hidden', false ).addClass( 'is-open' );
		$( 'body' ).addClass( 'abh-manual-guide-open' );
		window.setTimeout( function () { $( '.abh-manual-guide-close' ).trigger( 'focus' ); }, 0 );
	}

	function closeManualGuide() {
		$( '#abh-manual-guide-modal' ).prop( 'hidden', true ).removeClass( 'is-open' );
		$( 'body' ).removeClass( 'abh-manual-guide-open' );
		$( '#abh-console-manual-guide-inline, #abh-console-manual-guide' ).first().trigger( 'focus' );
	}

	function requestManualGuide( automatic ) {
		if ( repair.manualGuide ) {
			openManualGuide( repair.manualGuide );
			return resolvedPromise();
		}
		if ( ! repair.job ) { return resolvedPromise(); }
		var $buttons = $( '#abh-console-manual-guide-inline, #abh-console-manual-guide' ).prop( 'disabled', true );
		return request( 'manual_guide', { job: repair.job } ).then( function ( guide ) {
			guide.has_diff = hasUsableDiff( repair.diff );
			openManualGuide( guide );
			return guide;
		} ).fail( function ( err ) {
			if ( ! automatic ) {
				consoleLine( 'error', 'The manual guide could not be opened', err && err.message ? err.message : ABH.i18n.error );
			}
		} ).always( function () { $buttons.prop( 'disabled', false ); } );
	}

	// Un plan de operaciones no se enseña como un diff de una sola linea: son
	// cambios sobre el sitio, a veces en carpetas distintas. Esta edición no lo
	// aplica, así que el plan se pinta entero para que el dueño vea QUE se toca
	// y POR QUE antes de reproducirlo a mano o pasárselo a quien lo mantenga.
	function renderOperaciones( ops, avisos ) {
		if ( ! ops || ! ops.length ) { return ''; }
		var verbo = { escribir: 'Write', mover: 'Move', quitar: 'Remove', permisos: 'Permissions' };
		var filas = ops.map( function ( o ) {
			var destino = o.destino ? ' <span class="abh-op-flecha">&rarr;</span> <code>' + esc( o.destino ) + '</code>' : '';
			// Un cambio de permisos sin decir a cuáles es una casilla en blanco
			// en el único sitio donde el dueño puede decir que no.
			var modo    = o.modo ? ' <span class="abh-op-modo">' + esc( o.modo ) + '</span>' : '';
			var motivo  = o.motivo ? '<p class="abh-op-motivo">' + esc( o.motivo ) + '</p>' : '';
			// `o.op` viene del servidor y decoraba el atributo class por
			// concatenación. Va por addClass(), que no puede cerrar el atributo.
			var $li = $( '<li class="abh-op"></li>' ).addClass( 'abh-op-' + String( o.op || '' ) );
			$li.html( '<span class="abh-op-verbo">' + esc( verbo[ o.op ] || o.op ) + '</span> ' +
				'<code>' + esc( o.rel_path ) + '</code>' + destino + modo + motivo );
			return nodeHtml( $li );
		} ).join( '' );
		// Los avisos de sintaxis se pintan, no se esconden y no bloquean. Un
		// fragmento legítimo puede no compilar por sí solo, y el PHP que corre
		// aquí no siempre es el que ejecutará el archivo: la decisión es del
		// dueño, pero con el dato delante.
		var alerta = '';
		if ( avisos && avisos.length ) {
			// Se separan por lo que significan, no por su formato. Una señal de
			// capacidad —el parche mete algo que el archivo no tenía— no es lo
			// mismo que un reparo de sintaxis, y mezclarlas hace que la grave
			// se lea como una más de la lista.
			var caps = avisos.filter( function ( a ) { return 'capacidad' === a.tipo; } );
			var sint = avisos.filter( function ( a ) { return 'capacidad' !== a.tipo; } );
			var fila = function ( a ) {
				return '<li' + ( a.grave ? ' class="es-grave"' : '' ) + '><code>' + esc( a.rel_path ) + '</code> — ' + esc( a.detalle ) + '</li>';
			};
			if ( caps.length ) {
				var hayGrave = caps.some( function ( a ) { return !! a.grave; } );
				alerta += '<div class="abh-op-avisos' + ( hayGrave ? ' es-grave' : '' ) + '">' +
					'<strong>' + ( hayGrave
						? 'This change introduces capabilities the file did not have'
						: 'Note about what the patch changes' ) + '</strong>' +
					'<p>' + ( hayGrave
						? 'A patch that adds runtime evaluation, network calls, or user creation where none existed can disguise an unauthorized persistent change as a repair. Read these lines carefully before reproducing any of them by hand.'
						: 'This note alone is not a reason to discard the plan. Read the complete list below and weigh anything that touches several files, leaves wp-content, moves or removes files, or changes permissions.' ) + '</p><ul>' +
					caps.map( fila ).join( '' ) + '</ul></div>';
			}
			if ( sint.length ) {
				alerta += '<div class="abh-op-avisos"><strong>The syntax check has reservations</strong>' +
					'<p>A valid excerpt may not compile by itself, and the PHP version used by this panel may differ from the one running the file. Take it into account before reproducing the change by hand.</p><ul>' +
					sint.map( fila ).join( '' ) + '</ul></div>';
			}
		}
		return '<div class="abh-console-ops"><p class="abh-op-intro">' +
			'This repair does not fit in a single file. AI Bug Hunter will not apply it: the full plan is listed ' +
			'below so you, your developer, or your host can review it and decide. Back up the site before ' +
			'reproducing any of these steps.' +
			'</p>' + alerta + '<ul class="abh-op-lista">' + filas + '</ul></div>';
	}

	function showDiffReady( d, $btn ) {
		// La comparación terminó: el servidor dice en chat_open si con esto ya
		// hay algo concreto que preguntar.
		syncPrompt( d );
		rememberUsage( d );
		repair.token = d.token;
		repair.path = d.rel_path || repair.path;
		repair.sha = d.sha_before || repair.sha;
		repair.diff = d.diff || [];
		var hasActualDiff = hasUsableDiff( repair.diff );
		repair.result = d;
		repair.manualGuide = null;
		repair.environmentType = d.environment_type || '';

		var lines = [ hasActualDiff
			? [ 'ok', 'Diff prepared for manual review', 'The proposal passed the path and content safety gates. The site has not been modified and this edition cannot apply the change.' ]
			: [ 'warn', 'No downloadable diff was generated', 'The diagnosis is still available in Repair help, but there is no verified line-by-line change to download.' ] ];
		// El tick verde sólo cuando de verdad compiló. Desde que el lint es aviso
		// y no veto, `d.lint` puede traer el detalle de un FALLO — y pintarlo
		// bajo «Sintaxis comprobada» en verde decía justo lo contrario de lo que
		// había pasado. `lint_ok` es la bandera que lo distingue; si no viene
		// (respuestas de versiones anteriores) se conserva el comportamiento.
		// La primera línea del bloque afirmaba en verde que la propuesta «pasó …
		// la comprobación de sintaxis». Desde que el lint es aviso y no veto eso
		// puede ser falso, y se contradecía con la línea amarilla de dos más
		// abajo dentro del mismo cuadro. Se corrige aquí, sobre el array ya
		// construido, para no reescribir el texto en dos sitios distintos.
		var lintOkGlobal = ( 'undefined' === typeof d.lint_ok ) ? true : !! d.lint_ok;
		if ( ! lintOkGlobal && lines.length && lines[ 0 ] && 'string' === typeof lines[ 0 ][ 2 ] ) {
			lines[ 0 ][ 0 ] = 'warn';
			lines[ 0 ][ 2 ] = lines[ 0 ][ 2 ].replace(
				'the path gate, content safety gate, and syntax check',
				'the path and content safety gates, although the syntax check has reservations'
			);
		}
		if ( d.lint ) {
			var lintOk = lintOkGlobal;
			lines.push( lintOk
				? [ 'ok', 'Syntax checked', d.lint ]
				: [ 'warn', 'The syntax check has reservations', d.lint ] );
		}
		if ( d.explicacion && d.explicacion.tipo === 'sintoma' ) {
			lines.push( [ 'warn', 'The proposal only addresses the symptom', d.explicacion.que_no || 'The underlying cause would remain unresolved.' ] );
		}

		consoleSequence( lines );
		setProgress( 78 );
		setConsoleState( hasActualDiff ? 'Diff ready for review and manual application · 0 files modified' : 'Diagnosis ready · no diff available · 0 files modified', hasActualDiff ? 'is-safe' : 'is-warning' );
		var esPlan = d.modo === 'operaciones';
		var panel = '<div class="abh-console-section"><span class="abh-console-kicker ' + ( hasActualDiff ? 'is-ok' : 'is-warn' ) + '">' + ( esPlan ? 'PLAN FOR MANUAL REVIEW' : ( hasActualDiff ? 'DIFF READY' : 'DIAGNOSIS READY' ) ) + '</span>' +
			'<h3>' + esc( repair.path ) + '</h3>' +
			renderExplicacion( d.explicacion ) + renderFindings( d.findings ) +
			( d.modo === 'operaciones' ? renderOperaciones( ( d.txn && d.txn.ops ) ? d.txn.ops : d.operaciones, d.avisos ) : ( hasActualDiff ? '<details class="abh-console-diff-details" open><summary>View line-by-line change</summary>' + renderDiff( d.diff ) + '</details>' : '<p>No verified line-by-line change is available. Open Repair help for clear next steps.</p>' ) ) + renderUso( d ) + '</div>';
		appendPanelSection( 'diff', hasActualDiff ? 'Diff' : 'Diagnosis', panel, hasActualDiff ? 'is-ok' : 'is-warning' );
		var actions = '<button type="button" class="button button-primary" id="abh-console-manual-guide">What should I do?</button>' +
			( hasActualDiff ? '<button type="button" class="button" id="abh-console-download-diff">Download diff</button>' : '' ) +
			'<button type="button" class="button" id="abh-console-download-log">Download log</button>' +
			'<button type="button" class="button" data-console-close data-settle="declined">Reject</button>';
		// Aquí no hay botón de aplicar. Esta edición no escribe la propuesta: el
		// servidor no registra ninguna acción que la aplique, así que un botón
		// «Reparar instalación» sólo podía terminar en una petición rechazada.
		// Lo que sí sirve —la guía, el diff y el registro— queda arriba.
		setActions( actions );
		setManualGuideInline( true, 'What should I do?' );
		done( $btn );
		requestManualGuide( true );
		return resolvedPromise();
	}


	// Aquí vivían la confirmación escrita, el modo root y applyRepair(): todo el
	// camino que terminaba pidiendo al servidor que escribiera la propuesta en
	// disco. En esta edición esa acción no existe —no hay ninguna acción AJAX
	// registrada que la atienda—, así que el camino entero se ha retirado en vez
	// de dejar botones que siempre acababan en un rechazo. El diagnóstico, el
	// diff, la guía de reparación manual y el registro descargable se conservan:
	// son lo que esta edición sí puede entregar.

	function runGuardFix( $btn ) {
		openConsole( $btn, 'guard' );
		busy( $btn, 'Preparing change…' );
		repair.path = String( $btn.data( 'rel' ) || '' );
		$( '#abh-console-job' ).text( 'Local HUNTER AI · ' + repair.path );
		syncConsoleContext();
		setProgress( 24 );
		consoleSequence( [
			[ 'ai', 'Local repair opened', 'This case has a deterministic solution and does not require sending code to an API.' ],
			[ 'work', 'Reviewing the path and content', 'I will check that the file is within scope and that the guard does not already exist.' ]
		] )
			.then( function () { return requestIfConsoleOpen( 'guard_fix', { rel: repair.path }, $btn ); } )
			.then( function ( d ) {
				repair.job = 'HUNTER-LOCAL-' + Date.now();
				repair.sha = d.sha_before || repair.sha;
				$( '#abh-console-job' ).text( repair.job + ' · ' + repair.path );
				syncConsoleContext();
				return consoleLine( 'ok', 'Build frozen. Continuing with the scan.', 'The file identity was saved before preparing the change.', 'SHA-256: ' + ( d.sha_before || 'recorded' ) ).then( function () {
					return showDiffReady( d, $btn );
				} );
			} )
			.fail( failConsole );
	}

	function runEnvFix( $btn ) {
		openConsole( $btn, 'env' );
		busy( $btn, 'Reviewing permissions…' );
		$( '#abh-console-job' ).text( 'THOTH Environment Gate' );
		syncConsoleContext();
		setProgress( 20 );
		consoleLine( 'ai', 'I will review the permission change before applying it', 'A permission can restore operation while also exposing a sensitive file. That is why it is not changed blindly.' )
			.then( function () { return requestIfConsoleOpen( 'env_preview', { key: repair.key }, $btn ); } )
			.then( function ( d ) {
				repair.envToken = d.preview_token || '';
				var lines = [
					[ 'info', d.code + ' — ' + d.title, d.diagnosis ],
					[ d.sensitive_log ? 'warn' : 'ok', 'Proposed permissions: ' + ( d.mode_before || 'unknown' ) + ' → ' + d.mode_after, d.message ]
				];
				if ( d.sensitive_log ) {
					lines.push( [ 'warn', 'This alone does not close the debug exposure', 'Mode 600 will be used instead of 644. Even so, THOTH Security must recheck HTTP access, and in production the log should be disabled or moved outside the webroot.' ] );
				}
				return consoleSequence( lines ).then( function () {
					appendPanelSection( 'environment', 'Environment', '<div class="abh-console-section"><span class="abh-console-kicker ' + ( d.sensitive_log ? 'is-warn' : 'is-ok' ) + '">HUNTER AI LOCAL</span><h3>' + esc( d.title ) + '</h3><p>' + esc( d.diagnosis ) + '</p><h4>What will happen</h4>' + listHtml( d.steps ) + '<h4>Permissions</h4><p><code>' + esc( d.mode_before || '?' ) + '</code> → <code>' + esc( d.mode_after ) + '</code></p></div>', d.sensitive_log ? 'is-warning' : 'is-ok' );
					setProgress( 70 );
					setConsoleState( d.sensitive_log ? 'Partial correction · security rescan required' : 'Waiting for your authorization', 'is-waiting' );
					setActions( '<button type="button" class="button" id="abh-console-download-log">Download log</button><button type="button" class="button" data-console-close>Cancel</button><button type="button" class="button button-primary" id="abh-console-confirm-env">Apply permissions ' + esc( d.mode_after ) + '</button>' );
					done( $btn );
				} );
			} )
			.fail( failConsole );
	}

	function applyEnvFix() {
		setActions( '<button type="button" class="button" disabled>Applying permissions…</button>' );
		consoleLine( 'work', 'Applying the approved change', 'The server will revalidate the path, owner, and allowed permissions.' )
			.then( function () { return requestIfConsoleOpen( 'env_fix', { key: repair.key, preview_token: repair.envToken } ); } )
			.then( function ( d ) {
				return consoleSequence( [
					[ 'ok', 'Permissions updated', d.message ],
					[ 'info', 'The repair does not end here', 'Reload the diagnosis and run THOTH Security again. If the file remains accessible over HTTP, the finding remains open.' ]
				] ).then( function () {
					setProgress( 100 );
					setConsoleState( 'Permissions applied · external verification pending', 'is-warning' );
					setActions( postApplyActions() );
					if ( repair.$source ) { repair.$source.remove(); }
				} );
			} )
			.fail( failConsole );
	}


	$( document ).on( 'click', '.abh-syntax-scan', function ( e ) {
		e.preventDefault();
		runSyntaxScan( $( this ) );
	} );

	$( document ).on( 'click', '#abh-console-view-scan', function () {
		window.location.reload();
	} );

	$( document ).on( 'click', '.abh-analyze', function ( e ) {
		e.preventDefault();
		runThoth( $( this ) );
	} );

	$( document ).on( 'click', '.abh-guard-fix', function ( e ) {
		e.preventDefault();
		runGuardFix( $( this ) );
	} );

	$( document ).on( 'click', '.abh-env-fix', function ( e ) {
		e.preventDefault();
		runEnvFix( $( this ) );
	} );

	// Reparación a medias: el trabajo cifrado sigue vivo en el servidor, así que
	// una recarga no debe obligar a pagar otra vez el mismo análisis.
	function pintarReanudacion() {
		var a = ABH && ABH.active;
		if ( ! a || ! a.job_id || $( '.abh-resume' ).length ) { return; }
		// El gasto de esta reparación se cuenta al final, no aquí.
		var gasto = '';
		if ( a.meter && a.meter.total ) {
			gasto = ' Resuming does not repeat the completed analysis.';
		}
		var min = Math.max( 1, Math.round( ( a.caduca || 0 ) / 60 ) );
		var $c = $( '<div class="abh-resume"></div>' ).html(
			'<strong>You have a partial repair</strong>' +
			'<p><code>' + esc( a.rel_path || '' ) + '</code> — ' + esc( a.short || '' ) + '</p>' +
			'<p class="abh-muted">Phase: ' + esc( a.state || '' ) + '.' + esc( gasto ) + ' The encrypted session expires in about ' + min + ' min.</p>' +
			'<p><button type="button" class="button button-primary abh-resume-go">Resume where it stopped</button> ' +
			'<button type="button" class="button abh-resume-drop">Descartar</button></p>'
		);
		$( '.abh-list' ).first().before( $c );
	}

	$( document ).on( 'click', '.abh-resume-go', function () {
		var a = ( ABH && ABH.active ) || {};
		// Se reabre la consola sobre la MISMA incidencia: el trabajo cifrado
		// conserva la fase, así que no se reinicia el pipeline desde cero.
		// La clave viene del servidor y se metía sin escapar dentro de unas
		// comillas del selector. Se compara el atributo ya leído por el DOM,
		// igual que hace resolveIncidentInUi().
		var buscada = String( a.incident_key || '' );
		var $inc = $( '.abh-incident' ).filter( function () {
			return String( $( this ).attr( 'data-key' ) || '' ) === buscada;
		} );
		if ( $inc.length ) {
			$inc.find( '.abh-analyze' ).first().trigger( 'click' );
			return;
		}
		window.alert( 'The issue no longer appears in the list. The error may have resolved itself.' );
	} );

	$( document ).on( 'click', '.abh-resume-drop', function () {
		var $c = $( this ).closest( '.abh-resume' );
		$.post( ABH.ajax, { action: 'abh_thoth_discard', nonce: ABH.nonce } ).always( function () {
			if ( ABH ) { ABH.active = null; }
			$c.remove();
		} );
	} );

	$( function () { pintarReanudacion(); } );

	$( document ).on( 'click', '[data-console-close]', function ( e ) {
		e.preventDefault();
		// Rechazar cierra el medidor en el servidor: una reparación revisada y
		// no aplicada se cobra al mínimo, no como si se hubiera aplicado.
		var desenlace = $( this ).data( 'settle' );
		if ( desenlace && repair.job ) {
			$.post( ABH.ajax, { action: 'abh_thoth_settle', nonce: ABH.nonce, job: repair.job, outcome: desenlace } );
		}
		closeConsole();
	} );

	$( document ).on( 'keydown', function ( e ) {
		if ( e.key === 'Escape' && $( '#abh-manual-guide-modal' ).hasClass( 'is-open' ) ) {
			closeManualGuide();
			return;
		}
		if ( e.key === 'Escape' && $( '#abh-console' ).hasClass( 'is-open' ) ) {
			closeConsole();
		}
	} );

	$( document ).on( 'click', '#abh-console-toggle-pace', function () {
		repair.flushMessages = false;
		repair.paceAuto = false;
		repair.pace = repair.pace === 'fast' ? 'normal' : 'fast';
		if ( repair.wakeMessage ) { repair.wakeMessage(); }
		updatePaceLabel();
	} );

	$( document ).on( 'click', '#abh-console-show-all', function () {
		flushConsoleMessages();
	} );


	$( document ).on( 'click', '[data-console-tab], [data-console-tab-jump]', function () {
		var name = String( $( this ).data( 'console-tab' ) || $( this ).data( 'console-tab-jump' ) || 'analysis' );
		setConsoleView( name );
	} );

	$( document ).on( 'change', '#abh-console-autoscroll', function () {
		repair.autoScroll = $( this ).is( ':checked' );
		if ( repair.autoScroll ) { scrollConsole( true ); }
	} );

	$( document ).on( 'click', '#abh-console-pause', function () {
		repair.uiPaused = ! repair.uiPaused;
		var $button = $( this );
		$button.attr( 'aria-pressed', repair.uiPaused ? 'true' : 'false' ).toggleClass( 'is-paused', repair.uiPaused );
		$button.find( '.dashicons' ).attr( 'class', 'dashicons ' + ( repair.uiPaused ? 'dashicons-controls-play' : 'dashicons-controls-pause' ) );
		$button.find( 'span:last' ).text( repair.uiPaused ? 'Resume' : 'Pause' );
		if ( ! repair.uiPaused && repair.wakeMessage ) { repair.wakeMessage(); }
	} );

	// Salir de la consola recarga la página y se lleva reporte y registro.
	// Se pide confirmación explícita para no perder los archivos por un clic.
	$( document ).on( 'click', '.abh-leave-console', function ( e ) {
		if ( ! window.confirm( 'Leaving will close this console and you will no longer be able to download the report or log from here.\n\nHave you downloaded them? They are also saved under History → Download case file.\n\nSelect OK to leave or Cancel to stay.' ) ) {
			e.preventDefault();
		}
	} );

	// Expediente completo (reporte + registro + diff) desde Historial, en un ZIP.
	$( document ).on( 'click', '.abh-history-bundle', function () {
		var $b = $( this );
		var op = $b.data( 'op' );
		var previo = $b.text();
		$b.prop( 'disabled', true ).text( 'Preparing…' );
		request( 'export_history', { op: op } )
			.then( function ( d ) {
				downloadBase64( d.filename || 'HUNTER-case-file.zip', d.base64, d.mime || 'application/zip' );
			} )
			.fail( function ( err ) {
				window.alert( ( err && err.message ) || 'The case file could not be generated.' );
			} )
			.always( function () {
				$b.prop( 'disabled', false ).text( previo );
			} );
	} );

	// Chrome puede estrangular setTimeout tanto al ocultar una pestaña como al
	// perder el foco de la ventana. El diagnóstico ya no depende de la
	// reproducción visual, y cuando la persona se va completamos de golpe lo
	// pending para que al volver no encuentre una máquina de escribir
	// congelada. La pausa manual es la única excepción: esa intención sí se
	// conserva, aunque las peticiones del servidor continúan.
	function continueConsoleInBackground() {
		if ( repair.uiPaused || ! $( '#abh-console' ).hasClass( 'is-open' ) ) {
			return;
		}
		flushConsoleMessages();
		$( '#abh-console-pace-status' ).text( 'Background mode active · no animation' );
	}

	document.addEventListener( 'visibilitychange', function () {
		if ( document.hidden ) {
			continueConsoleInBackground();
		}
	} );
	window.addEventListener( 'blur', continueConsoleInBackground );

	$( document ).on( 'click', '#abh-console-explain-hash', function () {
		consoleLine( 'info', 'SHA-256 in plain language', 'It is a mathematical fingerprint of the file. It does not reveal the content, but changes completely if even one character changes. It prevents applying a diff to a different version.' );
	} );

	$( document ).on( 'click', '.abh-console-phase-link', function () {
		var id = String( $( this ).data( 'phase-target' ) || '' );
		var el = id ? document.getElementById( id ) : null;
		setConsoleView( 'events' );
		if ( el ) {
			window.setTimeout( function () {
				el.scrollIntoView( { behavior: 'smooth', block: 'start' } );
				el.open = true;
			}, 30 );
		}
	} );

	$( document ).on( 'click', '#abh-console-retry-evidence', function () {
		retryEvidenceRound();
	} );

	// Volver a pedir el parche con la evidencia que YA está recogida. No repite
	// el análisis ni el escaneo: sólo la fase que devolvió una respuesta mal
	// formada, que es la única que falló. Es el camino que convierte «no se
	// pudo» en «no salió a la primera».
	$( document ).on( 'click', '#abh-console-retry-fix', function () {
		$( this ).prop( 'disabled', true ).text( 'Retrying…' );
		retryEvidenceRound();
	} );

	// Reanalizar desde cero cuando la propuesta ya no existe. Se dispara la
	// misma tarjeta de la incidencia que la abrió, así que no hay un segundo
	// camino de análisis que mantener.
	$( document ).on( 'click', '#abh-console-reanalizar', function () {
		$( this ).prop( 'disabled', true ).text( 'Analyzing…' );
		if ( repair.$source && repair.$source.length ) {
			repair.$source.trigger( 'click' );
		} else {
			window.location.reload();
		}
	} );

	$( document ).on( 'click', '#abh-console-retry-contract', function () {
		retryContractPhase();
	} );

	$( document ).on( 'click', '#abh-console-manual-guide, #abh-console-manual-guide-inline', function () {
		requestManualGuide( false );
	} );

	$( document ).on( 'click', '[data-manual-guide-close]', function () {
		closeManualGuide();
	} );

	$( document ).on( 'click', '#abh-manual-guide-download', function () {
		if ( repair.manualGuide ) {
			download( ( repair.job || 'HUNTER' ) + '-manual-guide.txt', manualGuideText( repair.manualGuide ) );
		}
	} );

	$( document ).on( 'click', '#abh-manual-guide-download-diff', function () {
		if ( hasUsableDiff( repair.diff ) ) {
			download( ( repair.job || 'HUNTER-repair' ) + '.diff', diffText(), 'text/x-diff;charset=utf-8' );
		}
	} );

	$( document ).on( 'click', '#abh-console-download-report', function () {
		exportReport( false );
	} );

	$( document ).on( 'click', '#abh-console-open-report', function () {
		exportReport( true );
	} );

	$( document ).on( 'click', '#abh-console-download-diff', function () {
		if ( hasUsableDiff( repair.diff ) ) {
			download( ( repair.job || 'HUNTER-repair' ) + '.diff', diffText(), 'text/x-diff;charset=utf-8' );
		}
	} );

	$( document ).on( 'click', '#abh-console-download-log', function () {
		var etiquetas = { you: 'YOU', motor: 'MOTOR', ai: 'HUNTER AI', ok: 'READY', work: 'IN PROGRESS', warn: 'WARNING', error: 'STOP' };
		var text = repair.logs.map( function ( l ) {
			var etiqueta = etiquetas[ l.type ] || l.type.toUpperCase();
			return '[' + l.time + '] [' + etiqueta + '] ' + l.title + ( l.detail ? '\n  ' + l.detail : '' ) + ( l.code ? '\n  ' + l.code : '' );
		} ).join( '\n\n' ) + '\n';
		download( ( repair.job || 'HUNTER-console' ) + '-console.txt', text );
	} );

	// Reporte anónimo de un caso que no salió.
	//
	// Va a pasar muchas veces, y hasta ahora el caso moría en la pantalla de
	// quien lo sufrió. Se ENSEÑA el reporte entero y luego se descarga: el
	// plugin no lo manda a ninguna parte, así que la decisión es del dueño.
	$( document ).on( 'click', '#abh-console-report', function () {
		var $btn = $( this );
		busy( $btn, 'Preparing…' );
		claimFailure( post( 'report_preview', {
			job: repair.job || '',
			motivo: ( repair.lastFailure && repair.lastFailure.message ) || '',
			events: JSON.stringify( repair.logs || [] )
		} ) )
			.always( function () { done( $btn ); } )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				if ( ! res || ! res.success ) {
					consoleLine( 'warn', 'The report could not be prepared', d.message || ABH.i18n.error );
					return;
				}
				repair.reportJson = d.json || '';
				consoleLine(
					'info',
					'Read it before sharing — this review is the safeguard',
					'Your domain, server paths, plugin and file names, keys, email addresses, and IP addresses have been removed. The PHP error message remains unchanged because the report is not useful without it. If it contains the name of a class, table, or client, do not include it: edit the file before sharing it.',
					repair.reportJson
				).then( function () {
					// Sin botón de envío. Esta edición no manda nada a ningún
					// destino, así que el reporte se prepara, se enseña entero y se
					// descarga: quien lo sufre decide a dónde va y cuándo.
					var acciones = '<button type="button" class="button button-primary" id="abh-console-report-download">Download the report</button>' +
						'<span class="abh-muted abh-small">This edition never sends anything by itself: download the report and share it wherever you choose.</span>' +
						'<button type="button" class="button" data-console-close>Close</button>';
					setActions( acciones );
				} );
			} )
			.fail( function () {
				consoleLine( 'warn', 'The report could not be prepared', ABH.i18n.error );
			} );
	} );

	// El envío del reporte se retiró entero: no hay ningún destino al que este
	// plugin escriba por su cuenta, así que el único camino es la descarga.
	$( document ).on( 'click', '#abh-console-report-download', function () {
		download( ( repair.job || 'HUNTER' ) + '-anonymous-report.json', repair.reportJson || '{}', 'application/json;charset=utf-8' );
	} );

	// Ya no se enlazan #abh-console-approve, #abh-console-confirm-apply,
	// #abh-console-retry-apply ni #abh-console-force-apply: esos botones se
	// dejaron de pintar junto con el camino de aplicación. El permiso de
	// entorno sí se aplica en local, así que su confirmación se conserva.
	$( document ).on( 'click', '#abh-console-confirm-env', applyEnvFix );

	// Asesoría: se mantiene fuera de la consola de escritura.
	$( document ).on( 'click', '.abh-advise', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		var $box = $btn.closest( '.abh-incident' ).find( '.abh-result' );
		busy( $btn, ABH.i18n.analizando );
		$box.hide().empty();
		claimFailure( post( 'advise', { key: $btn.data( 'key' ) } ) )
			.always( function () { done( $btn ); } )
			.done( function ( res ) {
				var d = res.data || {};
				$box.html( res.success ? '<div class="abh-advice">' + d.html + '</div>' + renderUso( d ) : '<p class="abh-msg-err">' + esc( d.message || ABH.i18n.error ) + '</p>' ).show();
			} )
			.fail( function () { $box.html( '<p class="abh-msg-err">' + esc( ABH.i18n.error ) + '</p>' ).show(); } );
	} );

	// Revertir desde Historial.
	$( document ).on( 'click', '.abh-rollback', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		var force = $btn.data( 'force' ) ? '1' : '0';
		if ( force === '0' && ! window.confirm( ABH.i18n.revertir ) ) { return; }
		busy( $btn, ABH.i18n.aplicando );
		claimFailure( post( 'rollback', { op: $btn.data( 'op' ), force: force } ) )
			.always( function () { done( $btn ); } )
			.done( function ( res ) {
				var d = res.data || {};
				if ( res.success ) {
					$btn.closest( 'tr' ).find( '.abh-state' ).removeClass( 'abh-state-ok' ).addClass( 'abh-state-back' ).text( 'reverted' );
					$btn.replaceWith( '<span class="abh-msg-ok">✅</span>' );
				} else if ( d.needs_force ) {
					$btn.after( '<p class="abh-msg-err">' + esc( d.message ) + '</p>' ).data( 'force', true ).text( 'Revert anyway' );
				} else {
					$btn.after( '<p class="abh-msg-err">' + esc( d.message || ABH.i18n.error ) + '</p>' );
				}
			} )
			// Si la petición ni siquiera llega a responder, el botón tiene que
			// volver a estar pulsable y decir qué pasó. Callarse hacía que
			// «Revertir» pareciera un botón muerto.
			.fail( function () {
				$btn.prop( 'disabled', false );
				$btn.siblings( '.abh-spinner' ).remove();
				$btn.after( '<p class="abh-msg-err">' + esc( 'The revert request failed and nothing was reverted. Reload the page and try again.' ) + '</p>' );
			} );
	} );

	$( document ).on( 'click', '.abh-dismiss', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		post( 'dismiss', { key: $btn.data( 'key' ) } ).done( function ( res ) {
			if ( res.success ) { $btn.closest( '.abh-incident' ).slideUp( 150, function () { $( this ).remove(); } ); }
		} );
	} );

	$( document ).on( 'click', '.abh-undismiss', function ( e ) { e.preventDefault(); post( 'undismiss' ).done( function () { window.location.reload(); } ); } );
	$( document ).on( 'click', '.abh-toggle-solved', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		var $list = $btn.closest( '.abh-solved-wrap' ).find( '.abh-solved' );
		$list.slideToggle( 150 );
		$btn.text( $list.is( ':visible' ) ? 'hide' : 'show' );
	} );

	$( document ).on( 'click', '.abh-toggle-info', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		var $list = $btn.closest( '.abh-informativas' ).find( '.abh-info-list' );
		$list.slideToggle( 150 );
		$btn.text( $list.is( ':visible' ) ? 'hide' : 'show' );
	} );

	$( document ).on( 'click', '.abh-test', function ( e ) {
		e.preventDefault();
		var $btn = $( this );
		var $out = $( '.abh-test-result' ).text( '' );
		busy( $btn, ABH.i18n.analizando );
		post( 'test', {
			provider: $( '#abh_provider' ).val() || '', model: $( '#abh_model' ).val() || '', api_key: $( '#abh_api_key' ).val() || '',
			base_url: $( '#abh_base_url' ).val() || '', endpoint_confirmed: $( '#abh_endpoint_confirmed' ).is( ':checked' ) ? '1' : '0',
			allow_private: $( '#abh_allow_private' ).is( ':checked' ) ? '1' : '0',
			external_service_consent: $( '#abh_external_service_consent' ).is( ':checked' ) ? '1' : '0'
		} ).always( function () { done( $btn ); } ).done( function ( res ) {
			var d = res.data || {};
			$out.attr( 'class', 'abh-test-result ' + ( res.success ? 'abh-msg-ok' : 'abh-msg-err' ) ).text( ( res.success ? '✅ ' : '⛔ ' ) + ( d.message || ABH.i18n.error ) );
		} );
	} );

	$( document ).on( 'click', '.abh-clear-log', function ( e ) {
		e.preventDefault();
		if ( ! window.confirm( 'This deletes the COMPLETE log, including errors you have not reviewed.\n\nTo remove only resolved errors, cancel and use “Clean up only what is already resolved.”\n\nDelete everything anyway?' ) ) { return; }
		post( 'clear_log' ).done( function () { window.location.reload(); } );
	} );

	// Limpieza selectiva: quita del registro solo lo ya reparado u ocultado y
	// conserva lo que aún no se ha revisado. Primero informa qué va a quitar.
	$( document ).on( 'click', '.abh-purge-resolved', function ( e ) {
		e.preventDefault();
		var $a = $( this );
		$a.text( 'Reviewing…' );
		claimFailure( post( 'purge_resolved', { dry_run: '1' } ) )
			.done( function ( res ) {
				var d = res.data || {};
				var msg = 'The following will be removed: ' + ( d.removed || 0 ) + ' resolved error entries.\n' +
			'The following will be kept: ' + ( d.kept || 0 ) + ' unreviewed entries.\n\nContinue?';
				if ( ! window.confirm( msg ) ) { $a.text( 'Clean up only what is already resolved' ); return; }
				claimFailure( post( 'purge_resolved', { dry_run: '0' } ) )
					.done( function () { window.location.reload(); } )
					.fail( function ( x ) {
						$a.text( 'Clean up only what is already resolved' );
						window.alert( ( ( x.responseJSON || {} ).data || {} ).message || 'The log could not be cleaned.' );
					} );
			} )
			.fail( function ( x ) {
				$a.text( 'Clean up only what is already resolved' );
				window.alert( ( ( x.responseJSON || {} ).data || {} ).message || 'There are no resolved entries to clean.' );
			} );
	} );
	$( document ).on( 'click', '.abh-purge', function ( e ) {
		e.preventDefault();
		if ( ! window.confirm( 'Delete all backups and history?' ) ) { return; }
		var $btn = $( this );
		busy( $btn, ABH.i18n.aplicando );
		claimFailure( post( 'purge' ) ).always( function () { done( $btn ); } ).done( function ( res ) {
			$btn.after( '<span class="abh-msg-ok" style="margin-left:8px">' + esc( ( res.data || {} ).message || '' ) + '</span>' );
		} )
			// La purga se puede negar cuando hay una reparación a medias. Sin
			// esto la negativa era invisible: el botón volvía a la normalidad y
			// el dueño se quedaba creyendo que había borrado algo.
			.fail( function ( x ) {
				var d = ( x.responseJSON || {} ).data || {};
				$btn.after( '<span class="abh-msg-err" style="margin-left:8px">' + esc( d.message || 'It could not be deleted.' ) + '</span>' );
			} );
	} );

	/* ------------------------------------------------------------------ *
	 * El prompt de la terminal.
	 *
	 * Vivía en un panel flotante con su propio icono a la derecha: para
	 * preguntar sobre la reparación que tienes delante había que salir de la
	 * pantalla donde está la reparación. Ahora se escribe aquí y la respuesta
	 * se imprime en este mismo flujo, entre el razonamiento de HUNTER.
	 *
	 * Va DENTRO de este módulo a propósito: necesita consoleLine() y el
	 * identificador del trabajo, que son de aquí. Sacarlo fuera obligaba a
	 * adivinar el trabajo leyendo la cabecera con una expresión regular, que es
	 * justo lo que hacía la versión anterior.
	 * ------------------------------------------------------------------ */
	var promptBusy = false;

	// Abre la línea de la terminal para quien no es superadministración: solo
	// cuando la comparación terminó y queda algo concreto delante. El servidor
	// aplica el mismo criterio en ABH_Chat::open_for(); esto es la pantalla.
	// Refleja lo que dice el servidor. NO decide nada por su cuenta.
	//
	// Dos reglas, y las dos vienen de errores reales:
	//
	//  · Si la respuesta no trae chat_open, no se toca nada. Hay endpoints que
	//    no pasan por thoth_reply —aplicar, revertir, el arreglo del guardián,
	//    un fallo de transporte— y tratar su ausencia como «cerrar» apagaba la
	//    terminal justo en el fallo que existe para explicar.
	//  · A la superadministración no se le cierra nunca. Su formulario nace
	//    marcado como abierto de forma permanente y esta función lo respeta.
	function syncPrompt( d ) {
		var $form = $( '#abh-console-prompt' );
		if ( ! $form.length ) { return; }
		if ( 'siempre' === $form.attr( 'data-gated' ) ) { return; }
		if ( ! d || 'undefined' === typeof d.chat_open ) { return; }

		var abrir = !! d.chat_open;
		if ( abrir === ( '0' === $form.attr( 'data-gated' ) ) ) { return; }
		$form.toggleClass( 'is-gated', ! abrir ).attr( 'data-gated', abrir ? '0' : '1' );
		$( '#abh-console-input' )
			.prop( 'disabled', ! abrir )
			.attr( 'placeholder', abrir
				? 'Ask anything about this — press Enter to send'
				: 'Opens when the comparison finishes and a decision remains' );
		$( '#abh-console-send' ).prop( 'disabled', ! abrir );
	}

	$( document ).on( 'submit', '#abh-console-prompt', function ( e ) {
		e.preventDefault();
		if ( promptBusy ) { return; }

		var $input = $( '#abh-console-input' );
		var texto  = $.trim( $input.val() );
		if ( ! texto ) { return; }

		promptBusy = true;
		$input.val( '' ).prop( 'disabled', true );
		$( '#abh-console-send' ).prop( 'disabled', true ).text( 'Pensando…' );

		// Lo que escribe la persona entra en el MISMO registro que el resto.
		// Así el archivo que se descarga es la sesión completa, no la mitad.
		repair.chat = repair.chat || [];
		repair.chat.push( { role: 'user', content: texto } );

		// El título del registro se acota a 400 caracteres al exportarlo. Una
		// pregunta larga se guarda entera en el detalle para que el reporte no
		// la corte a la mitad.
		var titulo  = texto.length > 300 ? texto.slice( 0, 300 ) + '…' : texto;
		var detalle = texto.length > 300 ? texto : '';

		consoleLine( 'you', titulo, detalle )
			.then( function () {
				return $.post( ABH.ajax, {
					action: 'abh_chat',
					nonce: ABH.nonce,
					job: repair.job || '',
					messages: JSON.stringify( repair.chat )
				} );
			} )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				var respuesta = d.reply || 'No response was received.';
				repair.chat.push( { role: 'assistant', content: respuesta } );
				consoleLine( 'ai', respuesta, d.cost ? ( 'Usage for this response: ' + d.cost ) : '' );
				// Si el servidor dice que la puerta se cerró, se cierra ya, sin
				// esperar a la siguiente respuesta del flujo.
				syncPrompt( d );
			} )
			.fail( function ( x ) {
				var m = ( ( ( x || {} ).responseJSON || {} ).data || {} ).message || 'I could not respond right now.';
				consoleLine( 'warn', 'I could not respond', m );
			} )
			.always( function () {
				promptBusy = false;
				// Reabrir aquí sin mirar la puerta la volvía a abrir cuando se
				// había cerrado mientras esperábamos la respuesta. El estado de
				// la puerta lo decide syncPrompt; esto sólo quita el «Pensando…».
				var cerrado = ( '1' === $( '#abh-console-prompt' ).attr( 'data-gated' ) );
				$input.prop( 'disabled', cerrado );
				$( '#abh-console-send' ).prop( 'disabled', cerrado ).text( 'Send' );
				if ( ! cerrado ) { $input.trigger( 'focus' ); }
			} );
	} );

	// Liberar copias que ya no sirven para revertir nada.
	$( document ).on( 'click', '.abh-disco-limpiar', function () {
		var $b = $( this ), $m = $b.closest( '.abh-disco' ).find( '.abh-disco-msg' );
		$b.prop( 'disabled', true );
		$m.text( 'Releasing…' );
		$.post( ABH.ajax, { action: 'abh_health_prune', nonce: ABH.nonce } )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				$m.text( d.message || 'Done.' );
				if ( d.carpetas ) { window.setTimeout( function () { window.location.reload(); }, 1200 ); }
			} )
			.fail( function () { $m.text( 'The copies could not be released right now.' ); } )
			.always( function () { $b.prop( 'disabled', false ); } );
	} );

	// Al abrir la consola el cursor ya está en el prompt: es una terminal.
	$( document ).on( 'click', '.abh-analyze, .abh-advise, .abh-env-fix', function () {
		window.setTimeout( function () { $( '#abh-console-input' ).trigger( 'focus' ); }, 350 );
	} );
} )( jQuery );


/* Core integrity of WordPress · determinista, sin tokens. */
( function ( $ ) {
	'use strict';
	if ( 'undefined' === typeof ABH ) { return; }

	function escCore( s ) {
		return String( s == null ? '' : s ).replace( /[&<>"']/g, function ( c ) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ];
		} );
	}

	// Gemelo de nodeHtml() del otro cierre. Se repite a propósito: esc() y
	// nodeHtml() viven allí y aquí no existen —llamarlos lanzaba ReferenceError,
	// como ya pasó con el aviso de proveedor. Misma regla: un valor del servidor
	// que acabe DENTRO de un atributo se pone con .attr() sobre un nodo real.
	function nodeHtmlCore( $node ) {
		return ( $node && $node.length ) ? ( $node.prop( 'outerHTML' ) || '' ) : '';
	}

	function paso( $out, $btn ) {
		$.post( ABH.ajax, { action: 'abh_core_scan_step', nonce: ABH.nonce } )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				var pct = d.total ? Math.round( ( d.checked / d.total ) * 100 ) : 0;
				if ( ! d.done ) {
					$out.html( '<p class="abh-muted">Checking ' + d.checked + ' of ' + d.total + ' files (' + pct + '%)…</p>' );
					paso( $out, $btn );
					return;
				}
				var limpio = 0 === d.modified && 0 === d.missing;
				var html = '<div class="abh-core-report ' + ( limpio ? 'is-clean' : 'is-dirty' ) + '">' +
					'<p><strong>' + ( limpio ? '✅ Core intact' : '⚠ Core modified' ) + '</strong></p>' +
					'<p>' + escCore( d.message || '' ) + '</p>';
				function filaCore( f, falta ) {
					// La ruta la manda el servidor y entraba en data-file por
					// concatenación. Se pone con .attr() sobre el <li> real.
					var $li = $( '<li class="abh-core-file"></li>' ).attr( 'data-file', String( f == null ? '' : f ) );
					$li.html(
						'<code>' + escCore( f ) + '</code>' +
						'<span class="abh-core-actions">' +
						( falta ? '' : '<button type="button" class="button-link abh-core-diff">View difference</button>' ) +
						'<button type="button" class="button-link abh-core-restore">Restore official</button>' +
						( falta ? '' : '<button type="button" class="button-link abh-core-accept">I made this change intentionally</button>' ) +
						'</span><div class="abh-core-diffbox"></div>'
					);
					return nodeHtmlCore( $li );
				}
				if ( d.files_modified && d.files_modified.length ) {
					html += '<p><strong>Modified files</strong> — do not match the WordPress original:</p><ul class="abh-core-list">';
					d.files_modified.forEach( function ( f ) { html += filaCore( f, false ); } );
					html += '</ul>';
				}
				if ( d.files_missing && d.files_missing.length ) {
					html += '<p><strong>Missing files</strong> — should exist but are missing:</p><ul class="abh-core-list">';
					d.files_missing.forEach( function ( f ) { html += filaCore( f, true ); } );
					html += '</ul>';
				}
				if ( d.files_accepted && d.files_accepted.length ) {
					html += '<p class="abh-muted"><strong>Changes you marked as intentional</strong> (you will be notified if they change again):</p><ul class="abh-core-list is-accepted">';
					d.files_accepted.forEach( function ( f ) { html += '<li><code>' + escCore( f ) + '</code></li>'; } );
					html += '</ul>';
				}
				html += '</div>';
				$out.html( html );
				$btn.prop( 'disabled', false ).text( 'Check core integrity' );
			} )
			.fail( function ( x ) {
				var m = ( ( ( x.responseJSON || {} ).data ) || {} ).message || 'The check could not be completed.';
				$out.html( '<p class="abh-msg-warn">' + escCore( m ) + '</p>' );
				$btn.prop( 'disabled', false ).text( 'Check core integrity' );
			} );
	}

	// Aviso de consumo al cambiar de proveedor. Se pinta al elegir, no al
	// guardar: la decisión se toma con la información delante, no después.
	function notaProveedor( $sel, avisar ) {
		var $op = $sel.find( 'option:selected' );
		var $n  = $sel.closest( 'td' ).find( '.abh-provider-note' );
		var id  = $sel.val();
		if ( ! id ) { $n.empty(); return; }
		var nota    = $op.data( 'nota' ) || '';
		var propia  = 'service' === $op.data( 'billed' );
		var cls     = propia ? 'is-service' : 'is-customer';
		var titulo  = propia
			? 'This model uses tokens billed by our service'
			: 'This model uses tokens from your own account';
		// esc() vive en el otro cierre de este archivo y aquí no existe: llamarlo
		// lanzaba ReferenceError y el aviso de consumo no llegaba a pintarse
		// nunca. En este cierre el escapador es escCore.
		$n.html(
			'<div class="abh-provider-warn ' + cls + '">' +
			'<strong>' + escCore( titulo ) + '</strong>' +
			'<p>' + escCore( nota ) + '</p>' +
			( $op.data( 'key' ) === 1 || $op.data( 'key' ) === '1'
				? '<p class="abh-muted">You will need to paste your key below. It is never displayed after saving.</p>'
				: '<p class="abh-muted">You do not need to enter a key.</p>' ) +
			'</div>'
		);
		if ( avisar ) {
			$n.find( '.abh-provider-warn' ).addClass( 'is-fresh' );
			window.setTimeout( function () { $n.find( '.abh-provider-warn' ).removeClass( 'is-fresh' ); }, 1600 );
		}
	}

	$( document ).on( 'change', '#abh_provider', function () { notaProveedor( $( this ), true ); } );
	$( function () {
		var $p = $( '#abh_provider' );
		if ( $p.length ) { notaProveedor( $p, false ); }
	} );

	// Testigo: instalar, retirar y limpiar. Todo pasa por el mismo guardián de
	// permisos y nonce que el resto de acciones.
	function accionTestigo( $b, accion, confirmar ) {
		if ( confirmar && ! window.confirm( confirmar ) ) { return; }
		var $m = $( '.abh-watchdog-msg' ), txt = $b.text();
		$b.prop( 'disabled', true ).text( 'One moment…' );
		$.post( ABH.ajax, { action: 'abh_' + accion, nonce: ABH.nonce } )
			.always( function ( res ) {
				var d = ( res && res.data ) || {};
				var ok = res && res.success;
				$m.html( '<p class="' + ( ok ? 'abh-msg-ok' : 'abh-msg-warn' ) + '">' + escCore( d.message || 'It could not be completed.' ) + '</p>' );
				$b.prop( 'disabled', false ).text( txt );
				if ( ok ) { window.setTimeout( function () { window.location.reload(); }, 1200 ); }
			} );
	}

	$( document ).on( 'click', '.abh-watchdog-install', function () {
		accionTestigo( $( this ), 'watchdog_install', 'The watchdog will be installed at wp-content/mu-plugins/abh-watchdog.php. WordPress loads mu-plugins before everything else, allowing it to record fatal errors that bring the site down before this plugin can detect them.\n\nYou can remove it at any time from this panel.\n\nContinue?' );
	} );
	$( document ).on( 'click', '.abh-watchdog-uninstall', function () {
		accionTestigo( $( this ), 'watchdog_uninstall', 'The watchdog and its records will be removed. Fatal errors that never reach the log will no longer be reported.\n\nContinue?' );
	} );
	$( document ).on( 'click', '.abh-watchdog-clear', function () {
		accionTestigo( $( this ), 'watchdog_clear', '' );
	} );

	$( document ).on( 'click', '.abh-cve-refresh', function () {
		var $b = $( this ), $s = $( '.abh-cve-status' ), txt = $b.text();
		$b.prop( 'disabled', true ).text( 'Synchronizing…' );
		$.post( ABH.ajax, { action: 'abh_cve_refresh', nonce: ABH.nonce } )
			.always( function ( res ) {
				var d = ( res && res.data ) || {};
				$s.text( d.message || 'The feed could not be synchronized.' );
				$b.prop( 'disabled', false ).text( txt );
			} );
	} );

	$( document ).on( 'click', '.abh-core-scan', function () {
		var $btn = $( this );
		var $out = $( '.abh-core-result' );
		$btn.prop( 'disabled', true ).text( 'Checking…' );
		$out.html( '<p class="abh-muted">Requesting official fingerprints from WordPress.org…</p>' );
		$.post( ABH.ajax, { action: 'abh_core_scan_start', nonce: ABH.nonce } )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				$out.html( '<p class="abh-muted">WordPress ' + escCore( d.version ) + ' · ' + d.total + ' files to check…</p>' );
				paso( $out, $btn );
			} )
			.fail( function ( x ) {
				var m = ( ( ( x.responseJSON || {} ).data ) || {} ).message || 'The check could not be started.';
				$out.html( '<p class="abh-msg-warn">' + escCore( m ) + '</p>' );
				$btn.prop( 'disabled', false ).text( 'Check core integrity' );
			} );
	} );

	// Acciones por archivo del núcleo: ver diferencia, restaurar o aceptar.
	function accionCore( $li, accion, texto ) {
		var f = $li.data( 'file' );
		var $box = $li.children( '.abh-core-diffbox' );
		$box.html( '<p class="abh-muted">' + texto + '</p>' );
		return $.post( ABH.ajax, { action: 'abh_' + accion, nonce: ABH.nonce, file: f } );
	}

	// «Call to undefined function X» nombra al archivo que la llama, no al que
	// debería definirla. Esto busca el segundo y ofrece repararlo ahí.
	function buscarCausa( $li, fn ) {
		var $box = $li.children( '.abh-core-diffbox' );
		$box.append( '<p class="abh-muted abh-core-blame-msg">Looking for the file that should define ' + escCore( fn ) + '()…</p>' );
		$.post( ABH.ajax, { action: 'abh_core_blame', nonce: ABH.nonce, fn: fn } )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				$li.find( '.abh-core-blame-msg' ).remove();
				if ( ! res || ! res.success || ! d.rel_path ) {
					$box.append( '<p class="abh-muted">' + escCore( d.message || 'The source could not be determined.' ) + '</p>' );
					if ( d.need_scan ) {
						$box.append( '<p><button type="button" class="button abh-core-scan">Check core integrity</button></p>' );
					}
					return;
				}
				// Misma regla que filaCore(): la ruta va por .attr(), no dentro
				// del atributo por concatenación.
				var $culpable = $( '<div class="abh-core-file"></div>' ).attr( 'data-file', String( d.rel_path == null ? '' : d.rel_path ) );
				$culpable.html(
					'<code>' + escCore( d.rel_path ) + '</code>' +
					'<span class="abh-core-actions">' +
					'<button type="button" class="button abh-core-diff">View difference</button>' +
					'<button type="button" class="button button-primary abh-core-restore">Restore official</button>' +
					'</span><div class="abh-core-diffbox"></div>'
				);
				$box.append(
					'<div class="abh-core-culprit">' +
					'<strong>🎯 Cause found</strong>' +
					'<p>' + escCore( d.message ) + '</p>' +
					nodeHtmlCore( $culpable ) + '</div>'
				);
			} )
			.fail( function () {
				$li.find( '.abh-core-blame-msg' ).remove();
				$box.append( '<p class="abh-msg-warn">The source search could not be completed.</p>' );
			} );
	}

	$( document ).on( 'click', '.abh-core-blame', function () {
		var $li = $( this ).closest( '.abh-core-file' );
		$( this ).prop( 'disabled', true );
		buscarCausa( $li, $( this ).data( 'fn' ) );
	} );

	$( document ).on( 'click', '.abh-core-diff', function () {
		var $li  = $( this ).closest( '.abh-core-file' );
		var $btn = $( this );
		var txt  = $btn.text();
		$btn.prop( 'disabled', true );
		accionCore( $li, 'core_file_diff', 'Retrieving the verified official file…' )
			.done( function ( res ) {
				var d = ( res && res.data ) || {};
				$btn.prop( 'disabled', false ).text( txt );

				// Idéntico al original: no hay nada que restaurar y decirlo
				// vale más que enseñar un recuadro vacío.
				if ( d.identical ) {
					$li.children( '.abh-core-diffbox' ).html( '<p class="abh-msg-ok">✅ ' + escCore( d.message || '' ) + '</p>' );
					$li.children( '.abh-core-actions' ).find( '.abh-core-restore, .abh-core-accept' ).remove();
					// Confirmado que este archivo está sano: la pregunta útil pasa
					// a ser dónde está de verdad la causa, y se responde sola.
					if ( $li.data( 'fn' ) ) { buscarCausa( $li, $li.data( 'fn' ) ); }
					return;
				}
				var filas = ( d.diff || [] ).map( function ( r ) {
					var c = 'add' === r.type ? 'is-add' : ( 'del' === r.type ? 'is-del' : '' );
					return '<div class="abh-core-diffrow ' + c + '">' + escCore( r.text || '' ) + '</div>';
				} ).join( '' );
				var vista = filas ? '<div class="abh-core-diffview">' + filas + '</div>' : '';
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-muted">' + escCore( d.message || '' ) + '</p>' + vista );

				// Con la diferencia delante ya tiene sentido ofrecer aceptarla.
				if ( ! d.faltante && ! $li.children( '.abh-core-actions' ).find( '.abh-core-accept' ).length ) {
					$li.children( '.abh-core-actions' ).append(
						' <button type="button" class="button-link abh-core-accept">I made this change intentionally</button>'
					);
				}
			} )
			.fail( function ( x ) {
				$btn.prop( 'disabled', false ).text( txt );
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-msg-warn">' + escCore( ( ( ( x.responseJSON || {} ).data ) || {} ).message || 'The files could not be compared.' ) + '</p>' );
			} );
	} );

	$( document ).on( 'click', '.abh-core-restore', function () {
		if ( ! window.confirm( 'This file will be replaced with the official WordPress file verified by fingerprint.\n\nAn encrypted backup will be saved and can be restored from History.\n\nContinue?' ) ) { return; }
		var $li = $( this ).closest( '.abh-core-file' );
		accionCore( $li, 'core_file_restore', 'Downloading and verifying the official file…' )
			.done( function ( res ) {
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-msg-ok">✅ ' + escCore( ( ( res && res.data ) || {} ).message || 'Restored.' ) + '</p>' );
				$li.children( '.abh-core-actions' ).remove();
			} )
			.fail( function ( x ) {
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-msg-warn">' + escCore( ( ( ( x.responseJSON || {} ).data ) || {} ).message || 'The file could not be restored.' ) + '</p>' );
				// Restaurar no procedía porque el archivo está sano: entonces la
				// pregunta pending es dónde está la causa de verdad.
				if ( $li.data( 'fn' ) ) { buscarCausa( $li, $li.data( 'fn' ) ); }
			} );
	} );

	$( document ).on( 'click', '.abh-core-accept', function () {
		var $li = $( this ).closest( '.abh-core-file' );
		accionCore( $li, 'core_file_accept', 'Recording the exception…' )
			.done( function ( res ) {
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-muted">' + escCore( ( ( res && res.data ) || {} ).message || '' ) + '</p>' );
				$li.children( '.abh-core-actions' ).remove();
			} )
			.fail( function ( x ) {
				$li.children( '.abh-core-diffbox' ).html( '<p class="abh-msg-warn">' + escCore( ( ( ( x.responseJSON || {} ).data ) || {} ).message || 'The exception could not be recorded.' ) + '</p>' );
			} );
	} );

	function copySupportText( value, $status ) {
		value = String( value || '' );
		if ( ! value ) { return; }

		function copied() {
			$status.text( 'Copied.' );
			window.setTimeout( function () { $status.text( '' ); }, 2400 );
		}

		if ( navigator.clipboard && window.isSecureContext ) {
			navigator.clipboard.writeText( value ).then( copied, function () {
				fallbackCopy();
			} );
			return;
		}

		fallbackCopy();

		function fallbackCopy() {
			var $temp = $( '<textarea readonly></textarea>' ).val( value ).css( { position: 'fixed', left: '-9999px' } ).appendTo( 'body' );
			$temp[ 0 ].select();
			try {
				document.execCommand( 'copy' );
				copied();
			} catch ( error ) {
				$status.text( 'Copy failed. Select and copy the text manually.' );
			}
			$temp.remove();
		}
	}

	function supportFeedbackText( $card ) {
		var type = $card.find( '.abh-feedback-type' ).val();
		var title = $card.find( '.abh-feedback-title' ).val().trim();
		var description = $card.find( '.abh-feedback-description' ).val().trim();
		var lines = [
			'AI Bug Hunter — ' + ( type === 'bug' ? 'Bug report' : 'Feature request' ),
			'',
			'Title: ' + title,
			'',
			type === 'bug' ? 'What happened:' : 'Problem or idea:',
			description
		];

		function section( label, selector ) {
			var value = $card.find( selector ).val().trim();
			if ( value ) { lines.push( '', label + ':', value ); }
		}

		if ( type === 'bug' ) {
			section( 'Steps to reproduce', '.abh-feedback-steps' );
			section( 'Expected result', '.abh-feedback-expected' );
		} else {
			section( 'Suggested workflow', '.abh-feedback-workflow' );
			section( 'Who benefits and why', '.abh-feedback-benefit' );
		}
		section( 'Optional technical details', '.abh-feedback-technical' );
		lines.push( '', 'Prepared manually from the AI Bug Hunter Support page. No site data was attached automatically.' );
		return lines.join( '\n' );
	}

	$( document ).on( 'click', '.abh-feedback-choice', function () {
		var $button = $( this );
		var $card = $button.closest( '.abh-feedback-card' );
		var type = $button.data( 'feedback-type' ) === 'feature' ? 'feature' : 'bug';
		$card.find( '.abh-feedback-choice' ).attr( 'aria-pressed', 'false' );
		$button.attr( 'aria-pressed', 'true' );
		$card.find( '.abh-feedback-type' ).val( type );
		$card.find( '.abh-feedback-bug-only' ).prop( 'hidden', type !== 'bug' );
		$card.find( '.abh-feedback-feature-only' ).prop( 'hidden', type !== 'feature' );
		$card.find( '.abh-feedback-form-title' ).text( type === 'bug' ? 'Report a bug' : 'Request a feature' );
		$card.find( '.abh-feedback-description-label' ).text( type === 'bug' ? 'What happened?' : 'What problem or idea should we explore?' );
		$card.find( '.abh-feedback-form' ).prop( 'hidden', false );
		$card.find( '.abh-feedback-status' ).text( '' );
		window.setTimeout( function () { $card.find( '.abh-feedback-title' ).trigger( 'focus' ); }, 0 );
	} );

	$( document ).on( 'click', '.abh-feedback-copy', function () {
		var $card = $( this ).closest( '.abh-feedback-card' );
		var form = $card.find( '.abh-feedback-form' )[ 0 ];
		if ( ! form || ! form.reportValidity() ) { return; }
		copySupportText( supportFeedbackText( $card ), $card.find( '.abh-feedback-status' ) );
	} );

	$( document ).on( 'submit', '.abh-feedback-form', function ( event ) {
		event.preventDefault();
		if ( ! this.reportValidity() ) { return; }
		var $card = $( this ).closest( '.abh-feedback-card' );
		var email = String( $card.data( 'feedback-email' ) || '' );
		if ( ! email ) {
			$card.find( '.abh-feedback-status' ).text( 'No feedback email is configured. Copy the report instead.' );
			return;
		}
		var type = $card.find( '.abh-feedback-type' ).val();
		var title = $card.find( '.abh-feedback-title' ).val().trim();
		var subject = 'AI Bug Hunter — ' + ( type === 'bug' ? 'Bug report' : 'Feature request' ) + ': ' + title;
		window.location.href = 'mailto:' + email + '?subject=' + encodeURIComponent( subject ) + '&body=' + encodeURIComponent( supportFeedbackText( $card ) );
	} );

	$( document ).on( 'click', '.abh-copy-value', function () {
		var $button = $( this );
		copySupportText( $button.data( 'copy-value' ), $button.closest( '.abh-apoyo-card, .abh-mistral-setup' ).find( '.abh-copy-status' ) );
	} );

	$( document ).on( 'click', '.abh-use-mistral-settings', function () {
		$( '#abh_provider' ).val( 'mistral' ).trigger( 'change' );
		$( '#abh_model' ).val( 'mistral-small-2603' );
		$( '#abh_base_url' ).val( '' );
		$( '#abh_endpoint_confirmed, #abh_allow_private' ).prop( 'checked', false );
		var $status = $( this ).closest( '.abh-mistral-setup' ).find( '.abh-copy-status' );
		$status.text( 'Recommended values filled in. Add your API key, grant consent, save, and test the connection.' );
		window.setTimeout( function () { $status.text( '' ); }, 6000 );
		$( '#abh_api_key' ).trigger( 'focus' );
	} );
} )( jQuery );
