/**
 * AI Bug Hunter — Efectos de consola (1.5.2-alpha59)
 *
 * Capa estrictamente visual. Vive FUERA de admin.js a propósito: admin.js ya
 * pasa de 2.600 líneas y esto no necesita ni un dato del motor. Todo lo que
 * hace aquí se deduce del DOM que la consola ya pinta —clases de estado, ancho
 * de la barra de progreso, texto del pie—, así que no hay un segundo camino que
 * auditar ni una segunda fuente de verdad que pueda contradecir a la primera.
 *
 * Lo que añade:
 *   · Etiquetas tipo systemd: [  OK  ] [ EXEC ] [AVISO ] [ERROR ].
 *   · Cursor de bloque que persigue al texto que se está escribiendo.
 *   · Secuencia de arranque al abrir. Dice cosas ciertas SOBRE LA CONSOLA
 *     —versión, aislamiento, DRY-RUN—, nunca sobre el sitio: inventar hallazgos
 *     de adorno sería exactamente lo que el producto promete no hacer.
 *   · Spinner braille + cronómetro mientras hay trabajo en curso.
 *   · Medidor de progreso en bloques y reloj de sesión en la barra de ayuda.
 *
 * No toca el ritmo de reproducción: no encola, no espera y no retrasa ninguna
 * line. “Speed up” and “Show all” continue to work as before.
 */
( function () {
	'use strict';

	var BRAILLE = [ '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' ];

	// Seis caracteres dentro de los corchetes en todos los casos: si la columna
	// no cuadra al pixel, deja de leerse como salida de consola.
	var ETIQUETAS = {
		ok:    '[  OK  ]',
		work:  '[ EXEC ]',
		info:  '[ INFO ]',
		warn:  '[AVISO ]',
		error: '[ERROR ]',
		motor: '[MOTOR ]',
		ai:    '[HUNTER]',
		you:   '[  YOU  ]'
	};

	var TIPOS = Object.keys( ETIQUETAS );

	var reduce = window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;

	var estado = {
		abierta: false,
		inicio: 0,
		tick: null,
		giro: 0,
		caret: null,
		celebrado: false
	};

	function uno( sel, raiz ) { return ( raiz || document ).querySelector( sel ); }

	function tipoDeLinea( el ) {
		for ( var i = 0; i < TIPOS.length; i++ ) {
			if ( el.classList.contains( 'is-' + TIPOS[ i ] ) ) { return TIPOS[ i ]; }
		}
		return 'info';
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Etiquetas systemd
	 * El texto accesible de la línea no se toca: vive en el aria-label del
	 * contenedor y sigue diciendo READY, WARNING o STOP en palabras. Esto es
	 * solo lo que ve el ojo.
	 * ───────────────────────────────────────────────────────────────────── */
	// El observador solo ve lo que se añade DESPUÉS de engancharse. Si una línea
	// llegó antes —orden de carga, una sesión que se reanuda tras recargar—, se
	// quedaría con la etiqueta antigua y la columna saldría mezclada. Se barre
	// entero al arrancar y al abrir: barato, y quita la dependencia del orden.
	function marcarTodo() {
		var lineas = document.querySelectorAll( '.abh-console-line' );
		for ( var i = 0; i < lineas.length; i++ ) { marcarEtiqueta( lineas[ i ] ); }
	}

	function marcarEtiqueta( linea ) {
		var etiqueta = linea.querySelector( '.abh-console-label' );
		if ( ! etiqueta || etiqueta.getAttribute( 'data-fx' ) === '1' ) { return; }
		var tipo = tipoDeLinea( linea );
		etiqueta.setAttribute( 'data-fx', '1' );
		etiqueta.setAttribute( 'data-fx-tipo', tipo );
		etiqueta.textContent = ETIQUETAS[ tipo ] || ETIQUETAS.info;
	}

	// Mientras una línea de trabajo se escribe, su corchete gira. Cuando
	// termina se queda en [ EXEC ] y deja de moverse: el giro significa «esto
	// está pasando ahora», no «esto es de color azul».
	function girarEtiquetas() {
		if ( reduce ) { return; }
		var vivas = document.querySelectorAll( '.abh-console-line.is-typing .abh-console-label[data-fx-tipo="work"]' );
		if ( ! vivas.length ) { return; }
		var frame = BRAILLE[ estado.giro % BRAILLE.length ];
		for ( var i = 0; i < vivas.length; i++ ) {
			vivas[ i ].textContent = '[  ' + frame + '   ]';
		}
	}

	function cerrarEtiquetasVivas() {
		var hechas = document.querySelectorAll( '.abh-console-line.is-complete .abh-console-label[data-fx-tipo]' );
		for ( var i = 0; i < hechas.length; i++ ) {
			var t = hechas[ i ].getAttribute( 'data-fx-tipo' );
			var esperado = ETIQUETAS[ t ] || ETIQUETAS.info;
			if ( hechas[ i ].textContent !== esperado ) { hechas[ i ].textContent = esperado; }
		}
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * El cursor
	 * admin.js escribe carácter a carácter en <strong>, luego en <p> y luego en
	 * <code>. El cursor sigue a la mutación, así que va donde de verdad está
	 * cayendo el texto en lugar de quedarse clavado en el título.
	 * ───────────────────────────────────────────────────────────────────── */
	function moverCaret( destino ) {
		if ( estado.caret === destino ) { return; }
		if ( estado.caret ) { estado.caret.classList.remove( 'abh-fx-caret' ); }
		estado.caret = destino || null;
		if ( estado.caret ) { estado.caret.classList.add( 'abh-fx-caret' ); }
	}

	// Solo persigue a los tres huecos que admin.js rellena. Cualquier otro nodo
	// que mute —la propia fila viva, el medidor— se ignora, o el cursor acabaría
	// saltando a sitios donde no se está escribiendo nada.
	function apuntarCaret( el ) {
		if ( ! el || el.nodeType !== 1 || ! el.closest ) { return; }
		if ( ! el.matches( '.abh-console-copy > strong, .abh-console-copy > p, .abh-console-copy > code' ) ) { return; }
		var linea = el.closest( '.abh-console-line' );
		if ( linea && linea.classList.contains( 'is-typing' ) && ! linea.classList.contains( 'is-boot' ) ) {
			moverCaret( el );
		}
	}

	function soltarCaret( linea ) {
		if ( estado.caret && linea.contains( estado.caret ) ) { moverCaret( null ); }
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Arranque
	 * Cuatro hechos comprobables sobre la propia consola. Ni un número del
	 * sitio, ni un módulo inventado, ni una severidad de adorno: el arranque es
	 * decorado, y el decorado no puede afirmar nada que no sea verdad.
	 * ───────────────────────────────────────────────────────────────────── */
	function version() {
		if ( window.ABH && window.ABH.version ) { return String( window.ABH.version ); }
		var el = uno( '.abh-console-product-name span' );
		return el ? el.textContent.replace( /^v/, '' ) : '';
	}

	function hora() {
		var d = new Date();
		return [ d.getHours(), d.getMinutes(), d.getSeconds() ].map( function ( n ) {
			return String( n ).padStart( 2, '0' );
		} ).join( ':' );
	}

	function reloj( ms ) {
		var s = Math.max( 0, Math.floor( ms / 1000 ) );
		var m = Math.floor( s / 60 );
		return String( m ).padStart( 2, '0' ) + ':' + String( s % 60 ).padStart( 2, '0' );
	}

	function pintarArranque( terminal ) {
		var v = version();
		var lineas = [
			[ 'ok', 'HUNTER AI' + ( v ? ' · v' + v : '' ) ],
			[ 'ok', 'Isolated session · this console accepts questions only' ],
			[ 'ok', 'DRY-RUN · not a single byte is written without your prior approval' ],
			[ 'ok', 'Registro verificable activo · SHA-256' ]
		];
		var marca = hora();
		var html = '';
		for ( var i = 0; i < lineas.length; i++ ) {
			html += '<div class="abh-console-line is-boot is-' + lineas[ i ][ 0 ] + '" aria-hidden="true"' +
				' style="animation-delay:' + ( i * 55 ) + 'ms">' +
				'<span class="abh-console-time">[' + marca + ']</span>' +
				'<span class="abh-console-label" data-fx="1" data-fx-tipo="' + lineas[ i ][ 0 ] + '">' +
				ETIQUETAS[ lineas[ i ][ 0 ] ] + '</span>' +
				'<div class="abh-console-copy"><strong>' + lineas[ i ][ 1 ] + '</strong></div>' +
				'</div>';
		}
		html += '<div class="abh-fx-rule" aria-hidden="true">' +
			'── enlazando con el motor ──────────────────────────────</div>';
		terminal.insertAdjacentHTML( 'afterbegin', html );
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * El pipeline de agentes
	 * Seis actores del análisis adversarial, como chips sobre la terminal.
	 * Un actor se enciende cuando una línea real lo nombra y queda con ✓
	 * cuando habla otro después. Nada se enciende sin una línea que lo diga.
	 * ───────────────────────────────────────────────────────────────────── */
	var AGENTES = [
		{ id: 'observer', nombre: 'OBSERVER', re: /\bobserver\b|observador/i },
		{ id: 'analyst',  nombre: 'ANALYST',  re: /\banalyst\b|analista/i },
		{ id: 'skeptic',  nombre: 'SKEPTIC',  re: /\bskeptic\b|esc[eé]ptic/i },
		{ id: 'referee',  nombre: 'REFEREE',  re: /\breferee\b|[áa]rbitro/i },
		{ id: 'fixer',    nombre: 'FIXER',    re: /\bfixer\b|fix planner/i },
		{ id: 'verifier', nombre: 'VERIFIER', re: /\bverifier\b|verificador|post-fix/i }
	];

	function crearPipeline( wrap, terminal ) {
		var franja = wrap.querySelector( '.abh-fx-pipeline' );
		if ( franja ) { return franja; }
		franja = document.createElement( 'div' );
		franja.className = 'abh-fx-pipeline';
		franja.setAttribute( 'aria-hidden', 'true' );
		var html = '';
		for ( var i = 0; i < AGENTES.length; i++ ) {
			if ( i ) { html += '<span class="abh-fx-flecha">›</span>'; }
			html += '<span class="abh-fx-agent" data-agente="' + AGENTES[ i ].id + '">' +
				'<i></i>' + AGENTES[ i ].nombre + '<span class="abh-fx-check">✓</span></span>';
		}
		franja.innerHTML = html;
		wrap.insertBefore( franja, terminal );
		return franja;
	}

	function reiniciarPipeline() {
		var chips = document.querySelectorAll( '.abh-fx-agent' );
		for ( var i = 0; i < chips.length; i++ ) {
			chips[ i ].classList.remove( 'is-live', 'is-done' );
			chips[ i ].removeAttribute( 'title' );
		}
	}

	function detectarAgente( texto ) {
		for ( var i = 0; i < AGENTES.length; i++ ) {
			if ( AGENTES[ i ].re.test( texto ) ) { return AGENTES[ i ].id; }
		}
		return '';
	}

	function encenderAgente( id, frase ) {
		var chips = document.querySelectorAll( '.abh-fx-agent' );
		for ( var i = 0; i < chips.length; i++ ) {
			var chip = chips[ i ];
			if ( chip.getAttribute( 'data-agente' ) === id ) {
				chip.classList.remove( 'is-done' );
				chip.classList.add( 'is-live' );
				if ( frase ) { chip.setAttribute( 'title', frase ); }
			} else if ( chip.classList.contains( 'is-live' ) ) {
				chip.classList.remove( 'is-live' );
				chip.classList.add( 'is-done' );
			}
		}
	}

	// El agente que sigue «hablando» sin líneas nuevas: al completarse su línea
	// pasa a ✓ salvo que la siguiente también sea suya. Lo resuelve el latido:
	// si no hay línea escribiéndose, el live baja a done tras un par de ticks.
	var liveDesde = 0;
	function apagarSiCalla() {
		if ( document.querySelector( '.abh-console-line.is-typing' ) ) { liveDesde = estado.giro; return; }
		if ( estado.giro - liveDesde < 22 ) { return; }
		var vivo = document.querySelector( '.abh-fx-agent.is-live' );
		if ( vivo ) { vivo.classList.remove( 'is-live' ); vivo.classList.add( 'is-done' ); }
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Actores con cara: la línea 'ai' declara quién habla
	 * ───────────────────────────────────────────────────────────────────── */
	function nombrarActor( linea ) {
		if ( ! linea.classList.contains( 'is-ai' ) || linea.querySelector( '.abh-fx-actor' ) ) { return; }
		var texto = ( linea.getAttribute( 'aria-label' ) || linea.textContent || '' );
		var id = detectarAgente( texto );
		var copy = linea.querySelector( '.abh-console-copy' );
		if ( ! copy ) { return; }
		if ( id ) { linea.setAttribute( 'data-actor', id ); }
		var etiqueta = document.createElement( 'span' );
		etiqueta.className = 'abh-fx-actor';
		etiqueta.setAttribute( 'aria-hidden', 'true' );
		etiqueta.innerHTML = ( id ? id.toUpperCase() : 'HUNTER AI' ) + ' <small>· analysis agent</small>';
		copy.insertBefore( etiqueta, copy.firstChild );
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Banners de veredicto
	 * Solo hitos: error (alto), ok que confirma/verifica/prepara. El texto es
	 * el de la línea; el banner subraya, no redacta. Uno cada 6 s como mucho.
	 * ───────────────────────────────────────────────────────────────────── */
	var ultimoBanner = 0;
	// Hitos de verdad, no cualquier OK: si «Huella verificada» sacara banner,
	// el banner dejaría de significar algo a la tercera reparación.
	var RE_HITO_OK = /hallazgo confirmado|diff preparado|plan[^.]*preparad|reparaci[óo]n (aplicada|verificada)|sintaxis comprobada|cambio aplicado|incidencia resuelta/i;

	function veredicto( linea ) {
		if ( linea.classList.contains( 'is-boot' ) || linea.classList.contains( 'is-you' ) ) { return; }
		// El gran momento: reparación aplicada Y verificada. Se comprueba antes
		// que nada y no compite con el cooldown de los banners.
		var tituloExito = linea.querySelector( '.abh-console-copy strong' );
		tituloExito = tituloExito ? tituloExito.textContent : '';
		if ( ( linea.classList.contains( 'is-ok' ) || linea.classList.contains( 'is-motor' ) ) &&
			RE_EXITO.test( tituloExito ) && ! /sin cambios|no se|nada que/i.test( tituloExito ) ) {
			var det = linea.querySelector( '.abh-console-copy p' );
			celebrar( tituloExito + ( det && det.textContent ? ' — ' + det.textContent : '' ) );
			return;
		}
		var esAlto = linea.classList.contains( 'is-error' );
		var ahora = Date.now();
		// Un STOP nunca espera turno detrás de un OK rutinario.
		if ( ! esAlto && ahora - ultimoBanner < 6000 ) { return; }
		var titulo = linea.querySelector( '.abh-console-copy strong' );
		titulo = titulo ? titulo.textContent : '';
		if ( ! titulo ) { return; }
		var clase = '', sello = '';
		if ( linea.classList.contains( 'is-error' ) ) {
			clase = 'is-stop'; sello = 'STOP';
		} else if ( linea.classList.contains( 'is-ok' ) && RE_HITO_OK.test( titulo ) ) {
			clase = /preparad/i.test( titulo ) ? 'is-info' : 'is-ok';
			sello = 'is-info' === clase ? 'READY' : 'OK';
		}
		if ( ! clase ) { return; }
		ultimoBanner = ahora;
		var wrap = uno( '.abh-console-terminal-wrap' );
		if ( ! wrap ) { return; }
		var previo = wrap.querySelector( '.abh-fx-banner' );
		if ( previo ) { previo.remove(); }
		var banner = document.createElement( 'div' );
		banner.className = 'abh-fx-banner ' + clase;
		banner.setAttribute( 'aria-hidden', 'true' );
		banner.innerHTML = '<strong>' + sello + '</strong>';
		banner.appendChild( document.createTextNode( titulo ) );
		wrap.appendChild( banner );
		window.setTimeout( function () { banner.remove(); }, 3800 );
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Una sola acción azul de reparación, visible junto a la terminal
	 * ───────────────────────────────────────────────────────────────────── */
	function sincronizarAplicar() {
		var reparar = document.getElementById( 'abh-console-aplicar' );
		var acciones = document.getElementById( 'abh-console-actions' );
		if ( ! reparar || ! acciones ) { return; }
		var accion = document.getElementById( 'abh-console-confirm-apply' )
			|| document.getElementById( 'abh-console-approve' );
		var conAck = !! ( accion && acciones.querySelector( '.abh-assisted-ack' ) );
		// La casilla asistida permanece en el pie, pero la acción que habilita
		// se muestra junto a la terminal. El original queda en el DOM para
		// conservar exactamente el mismo manejador, nonce y estado disabled.
		acciones.classList.toggle( 'abh-fx-con-ack', conAck );
		if ( accion ) {
			accion.hidden = true;
			accion.setAttribute( 'aria-hidden', 'true' );
			accion.tabIndex = -1;
			reparar.hidden = false;
			reparar.disabled = !! accion.disabled;
			reparar.textContent = accion.textContent || 'Repair installation';
			return;
		}
		if ( reparar.getAttribute( 'data-root-waiting' ) === '1' ) {
			reparar.hidden = false;
			reparar.disabled = false;
			reparar.textContent = 'Repair installation';
			return;
		}
		reparar.hidden = true;
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * LA CELEBRACIÓN
	 * Cuando una reparación se aplica y se verifica de verdad, sale un cartel
	 * grande con confeti. Una vez por sesión de consola: si saltara con cada
	 * «Huella verificada» dejaría de sentirse como una victoria.
	 * ───────────────────────────────────────────────────────────────────── */
	var RE_EXITO = /reparaci[óo]n (aplicada|verificada|completada|lista|correcta)|cambio aplicado y verificado|incidencia resuelta|qued[óo] resuelto|soluci[óo]n aplicada|bug[^.]*(arreglad|corregid|resuelt)/i;

	function confeti( capa ) {
		if ( reduce ) { return; }
		var colores = [ '#ef3b32', '#f37435', '#2468dc', '#ffffff', '#f5c542', '#9ba7b8' ];
		var frag = document.createDocumentFragment();
		for ( var i = 0; i < 70; i++ ) {
			var p = document.createElement( 'span' );
			p.className = 'abh-fx-confeti';
			// La posición y los tiempos varían por índice, no por azar
			// (Math.random no está disponible aquí y rompería el resume).
			var izq = ( ( i * 37 ) % 100 );
			var dur = 2.4 + ( ( i * 13 ) % 22 ) / 10;
			var retraso = ( ( i * 7 ) % 12 ) / 10;
			p.style.left = izq + '%';
			p.style.background = colores[ i % colores.length ];
			p.style.animationDuration = dur + 's';
			p.style.animationDelay = retraso + 's';
			if ( i % 3 === 0 ) { p.style.width = '7px'; p.style.height = '11px'; }
			if ( i % 4 === 0 ) { p.style.borderRadius = '50%'; }
			frag.appendChild( p );
		}
		capa.appendChild( frag );
	}

	function celebrar( detalle ) {
		if ( estado.celebrado ) { return; }
		var ventana = uno( '.abh-console-window' );
		if ( ! ventana ) { return; }
		estado.celebrado = true;

		var capa = document.createElement( 'div' );
		capa.className = 'abh-fx-celebra';
		capa.setAttribute( 'role', 'alertdialog' );
		capa.setAttribute( 'aria-live', 'assertive' );
		capa.setAttribute( 'aria-label', 'Done! Bug found and fixed.' );
		capa.innerHTML =
			'<div class="abh-fx-celebra-card">' +
				'<div class="abh-fx-celebra-medalla" aria-hidden="true">✓</div>' +
				'<h2>DONE!</h2>' +
				'<p class="abh-fx-celebra-sub">Bug encontrado y arreglado</p>' +
				( detalle ? '<p class="abh-fx-celebra-detalle">' + esc( detalle ) + '</p>' : '' ) +
				'<p class="abh-fx-celebra-firma">See you on the next hunt 💚</p>' +
				'<button type="button" class="abh-fx-celebra-cerrar">Continue</button>' +
			'</div>';
		confeti( capa );
		ventana.appendChild( capa );

		function cerrar() {
			if ( capa.parentNode ) { capa.parentNode.removeChild( capa ); }
			window.clearTimeout( reloj );
		}
		capa.querySelector( '.abh-fx-celebra-cerrar' ).addEventListener( 'click', cerrar );
		capa.addEventListener( 'click', function ( e ) { if ( e.target === capa ) { cerrar(); } } );
		var reloj = window.setTimeout( cerrar, 7000 );
	}

	// El cierre verificado es un dato del motor, no una frase para interpretar.
	// admin.js emite este evento únicamente cuando verdict === verified. El
	// detector por texto de arriba permanece como compatibilidad con rutas
	// antiguas, y estado.celebrado evita que ambos caminos dupliquen el cartel.
	document.addEventListener( 'abh:repair-verified', function ( event ) {
		var detail = event && event.detail ? event.detail : {};
		var copy = [ detail.title || '', detail.message || '' ].filter( Boolean ).join( ' — ' );
		celebrar( copy );
	} );

	function esc( s ) {
		return String( s == null ? '' : s ).replace( /[&<>"]/g, function ( c ) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ c ];
		} );
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * La fila viva del final y el medidor de la barra de ayuda
	 * ───────────────────────────────────────────────────────────────────── */
	function filaEstado( terminal ) {
		var fila = terminal.querySelector( '.abh-fx-status' );
		if ( ! fila ) {
			fila = document.createElement( 'div' );
			fila.className = 'abh-fx-status';
			fila.setAttribute( 'aria-hidden', 'true' );
			fila.innerHTML = '<span class="abh-fx-spin">·</span><span class="abh-fx-texto"></span>' +
				'<span class="abh-fx-elapsed">00:00</span>';
			terminal.appendChild( fila );
		} else if ( fila !== terminal.lastElementChild ) {
			// Cada línea nueva se añade DETRÁS. La fila viva vuelve al final o
			// deja de estar donde tiene sentido que esté.
			terminal.appendChild( fila );
		}
		return fila;
	}

	function medidor() {
		var ayuda = uno( '.abh-console-help' );
		if ( ! ayuda ) { return null; }
		var m = ayuda.querySelector( '.abh-fx-meter' );
		if ( ! m ) {
			m = document.createElement( 'span' );
			m.className = 'abh-fx-meter';
			m.setAttribute( 'aria-hidden', 'true' );
			m.innerHTML = '<b></b><i></i>';
			var playback = ayuda.querySelector( '.abh-console-playback' );
			if ( playback ) { ayuda.insertBefore( m, playback ); } else { ayuda.appendChild( m ); }
		}
		return m;
	}

	function porcentaje() {
		var barra = document.getElementById( 'abh-console-progress-bar' );
		if ( ! barra ) { return 0; }
		var n = parseFloat( barra.style.width || '' );
		if ( isNaN( n ) ) {
			var padre = barra.parentElement;
			if ( ! padre || ! padre.offsetWidth ) { return 0; }
			n = barra.offsetWidth * 100 / padre.offsetWidth;
		}
		return Math.max( 0, Math.min( 100, Math.round( n ) ) );
	}

	function bloques( pct ) {
		var llenos = Math.round( pct / 10 );
		var s = '';
		for ( var i = 0; i < 10; i++ ) { s += i < llenos ? '█' : '░'; }
		return s;
	}

	function hayTrabajo() {
		if ( document.querySelector( '.abh-console-line.is-typing' ) ) { return true; }
		var scan = document.getElementById( 'abh-console-scan-state' );
		return !! ( scan && scan.classList.contains( 'is-working' ) );
	}

	function tono() {
		var scan = document.getElementById( 'abh-console-scan-state' );
		if ( ! scan ) { return ''; }
		if ( scan.classList.contains( 'is-error' ) ) { return 'is-error'; }
		if ( scan.classList.contains( 'is-warning' ) ) { return 'is-warn'; }
		if ( scan.classList.contains( 'is-ok' ) ) { return 'is-ok'; }
		return '';
	}

	function latido() {
		if ( ! estado.abierta ) { return; }
		estado.giro++;

		var terminal = document.getElementById( 'abh-console-terminal' );
		var elapsed = reloj( Date.now() - estado.inicio );
		var trabajando = hayTrabajo();

		if ( terminal ) {
			var fila = filaEstado( terminal );
			var pie = document.getElementById( 'abh-console-state' );
			fila.className = 'abh-fx-status ' + tono();
			fila.querySelector( '.abh-fx-spin' ).textContent = trabajando
				? ( reduce ? '•' : BRAILLE[ estado.giro % BRAILLE.length ] )
				: '·';
			fila.querySelector( '.abh-fx-texto' ).textContent = pie ? pie.textContent : '';
			fila.querySelector( '.abh-fx-elapsed' ).textContent = elapsed;
			girarEtiquetas();
			cerrarEtiquetasVivas();
			apagarSiCalla();
		}
		sincronizarAplicar();

		var m = medidor();
		if ( m ) {
			var pct = porcentaje();
			m.querySelector( 'b' ).textContent = bloques( pct ) + ' ' + pct + '%';
			m.querySelector( 'i' ).textContent = '· ' + elapsed;
			var pista = uno( '.abh-console-progress' );
			if ( pista ) { pista.classList.toggle( 'is-idle', ! trabajando || pct >= 100 ); }
		}
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * Enganches
	 * ───────────────────────────────────────────────────────────────────── */
	function abrir() {
		if ( estado.abierta ) { return; }
		estado.abierta = true;
		estado.inicio = Date.now();
		estado.giro = 0;
		estado.celebrado = false;
		moverCaret( null );
		var terminal = document.getElementById( 'abh-console-terminal' );
		if ( terminal ) {
			var wrap = terminal.closest( '.abh-console-terminal-wrap' );
			if ( wrap ) { crearPipeline( wrap, terminal ); }
			reiniciarPipeline();
			pintarArranque( terminal );
			marcarTodo();
			filaEstado( terminal );
		}
		if ( estado.tick ) { window.clearInterval( estado.tick ); }
		estado.tick = window.setInterval( latido, 90 );
		latido();
	}

	function cerrar() {
		estado.abierta = false;
		if ( estado.tick ) { window.clearInterval( estado.tick ); estado.tick = null; }
		moverCaret( null );
	}

	function observarConsola( consola ) {
		new MutationObserver( function () {
			if ( consola.classList.contains( 'is-open' ) ) { abrir(); } else { cerrar(); }
		} ).observe( consola, { attributes: true, attributeFilter: [ 'class' ] } );
		if ( consola.classList.contains( 'is-open' ) ) { abrir(); }
	}

	function observarTerminal( terminal ) {
		new MutationObserver( function ( mutaciones ) {
			for ( var i = 0; i < mutaciones.length; i++ ) {
				var mu = mutaciones[ i ];

				if ( mu.type === 'childList' ) {
					for ( var j = 0; j < mu.addedNodes.length; j++ ) {
						var nodo = mu.addedNodes[ j ];
						if ( nodo.nodeType === 1 && nodo.classList.contains( 'abh-console-line' ) ) {
							marcarEtiqueta( nodo );
							nombrarActor( nodo );
							if ( ! nodo.classList.contains( 'is-boot' ) ) {
								var agente = detectarAgente( nodo.getAttribute( 'aria-label' ) || nodo.textContent || '' );
								if ( agente ) {
									var frase = nodo.querySelector( '.abh-console-copy strong' );
									encenderAgente( agente, frase ? frase.textContent : '' );
									liveDesde = estado.giro;
								}
							}
							// La fila viva baja YA, no en el siguiente latido. Noventa
							// milisegundos con la línea nueva por debajo del cursor se
							// ven, y se ven como un fallo de pintado.
							if ( estado.abierta ) { filaEstado( terminal ); }
						}
					}
					// Y aquí es donde se sigue el tecleo. jQuery .text( valor ) hace
					// empty() + createTextNode: eso son mutaciones childList sobre el
					// <strong>, el <p> o el <code>, NO characterData. Escuchando solo
					// characterData el cursor no aparecía nunca.
					apuntarCaret( mu.target );
					continue;
				}

				if ( mu.type === 'characterData' ) {
					// Por si alguna ruta escribe con textContent directo.
					apuntarCaret( mu.target.parentElement );
					continue;
				}

				if ( mu.type === 'attributes' && mu.target.classList &&
					mu.target.classList.contains( 'abh-console-line' ) &&
					! mu.target.classList.contains( 'is-typing' ) ) {
					soltarCaret( mu.target );
					if ( mu.target.classList.contains( 'is-complete' ) &&
						mu.target.getAttribute( 'data-fx-veredicto' ) !== '1' ) {
						mu.target.setAttribute( 'data-fx-veredicto', '1' );
						veredicto( mu.target );
					}
				}
			}
		} ).observe( terminal, {
			childList: true,
			subtree: true,
			characterData: true,
			attributes: true,
			attributeFilter: [ 'class' ]
		} );
	}

	// Mientras el modal de firma root esta arriba, la consola queda inerte.
	// Subirlo de z-index lo arreglo para el ojo; para un lector de pantalla
	// seguian existiendo DOS aria-modal="true" a la vez y el foco se quedaba
	// atrapado en el dialogo de la consola, que es justo el que ya no manda.
	// 'inert' hace las dos cosas de golpe: lo saca del arbol de accesibilidad y
	// le quita el foco a todo lo que hay dentro.
	function vigilarModalRoot( consola ) {
		var ventana = consola.querySelector( '.abh-console-window' );
		if ( ! ventana ) { return; }
		new MutationObserver( function () {
			var abierto = !! document.getElementById( 'abh-root-modal' );
			if ( abierto === ventana.hasAttribute( 'inert' ) ) { return; }
			if ( abierto ) {
				ventana.setAttribute( 'inert', '' );
				ventana.setAttribute( 'aria-hidden', 'true' );
			} else {
				ventana.removeAttribute( 'inert' );
				ventana.removeAttribute( 'aria-hidden' );
			}
		} ).observe( document.body, { childList: true } );
	}

	function arrancar() {
		var consola = document.getElementById( 'abh-console' );
		var terminal = document.getElementById( 'abh-console-terminal' );
		if ( ! consola || ! terminal ) { return; }
		document.addEventListener( 'abh:console-actions-changed', sincronizarAplicar );
		observarTerminal( terminal );
		marcarTodo();
		observarConsola( consola );
		vigilarModalRoot( consola );
		sincronizarAplicar();
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', arrancar );
	} else {
		arrancar();
	}
} )();
