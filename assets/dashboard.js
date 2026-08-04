/* global jQuery */
( function ( $ ) {
	'use strict';

	function organiseDashboardNotices() {
		var $page = $( '.abh-diagnostic-page' );
		var $tray = $( '#abh-notice-tray' );
		var $body = $( '#abh-notice-tray-body' );
		if ( ! $page.length || ! $tray.length || ! $body.length ) { return; }

		var $external = $( '#wpbody-content' ).children( '.notice, .updated, .error' );
		var $internal = $page.children( '.notice, .updated, .error' );
		$external.add( $internal ).filter( function () {
			return ! $( this ).hasClass( 'abh-notice-captured' ) && ! $( this ).closest( '#abh-notice-tray' ).length;
		} ).each( function () {
			// Aquí había un caso especial que BORRABA del DOM los avisos de
			// TGMPA. Se ha retirado: un plugin no elimina la salida de otro, y
			// la sonda por href alcanzaba a cualquier aviso que simplemente
			// enlazara a esa página. Ahora entran en la bandeja como todos los
			// demás —siguen visibles, contados y accesibles—, que es lo único
			// que esta pantalla necesitaba. No lo reintroduzcas: es la
			// guideline 11 de WordPress.org.
			$( this ).addClass( 'abh-notice-captured' ).appendTo( $body );
		} );

		var count = $body.children( '.notice, .updated, .error' ).length;
		$tray.prop( 'hidden', ! count );
		$tray.find( '.abh-notice-count' ).text( count );
	}

	function showFinding( $workspace, index ) {
		var count = Number( $workspace.attr( 'data-finding-count' ) || 0 );
		if ( ! count ) { return; }
		index = ( index + count ) % count;
		$workspace.data( 'active-index', index );
		$workspace.find( '.abh-finding-slide' ).prop( 'hidden', true ).filter( '[data-finding-index="' + index + '"]' ).prop( 'hidden', false );
		$( '.abh-context-set' ).prop( 'hidden', true ).filter( '[data-context-index="' + index + '"]' ).prop( 'hidden', false );
		$workspace.find( '[data-finding-current]' ).text( index + 1 );

		var $slide = $workspace.find( '.abh-finding-slide[data-finding-index="' + index + '"]' );
		var tone = String( $slide.attr( 'data-finding-tone' ) || 'warning' );
		var label = String( $slide.attr( 'data-finding-severity' ) || 'AVISO' );
		var $pill = $workspace.find( '[data-active-severity]' );
		$pill.removeClass( 'is-fatal is-warning' ).addClass( 'is-' + tone ).text( label );
	}

	$( document ).on( 'click', '.abh-notice-toggle', function () {
		var $button = $( this );
		var $body = $( '#abh-notice-tray-body' );
		var open = $button.attr( 'aria-expanded' ) === 'true';
		$button.attr( 'aria-expanded', open ? 'false' : 'true' );
		$body.prop( 'hidden', open );
		$button.find( '.dashicons-arrow-down-alt2, .dashicons-arrow-up-alt2' )
			.toggleClass( 'dashicons-arrow-down-alt2', open )
			.toggleClass( 'dashicons-arrow-up-alt2', ! open );
	} );

	$( document ).on( 'click', '.abh-finding-next, .abh-finding-prev', function () {
		var $workspace = $( this ).closest( '.abh-finding-workspace' );
		var current = Number( $workspace.data( 'active-index' ) || 0 );
		showFinding( $workspace, current + ( $( this ).hasClass( 'abh-finding-next' ) ? 1 : -1 ) );
	} );

	var scanSummaryTrigger = null;

	function closeScanSummary() {
		var modal = document.getElementById( 'abh-scan-summary-modal' );
		if ( ! modal || modal.hidden ) { return; }
		modal.hidden = true;
		document.body.classList.remove( 'abh-has-scan-summary-modal' );
		if ( scanSummaryTrigger ) {
			scanSummaryTrigger.setAttribute( 'aria-expanded', 'false' );
			scanSummaryTrigger.focus();
		}
	}

	$( document ).on( 'click', '.abh-open-scan-summary', function () {
		var modal = document.getElementById( 'abh-scan-summary-modal' );
		if ( ! modal ) { return; }
		scanSummaryTrigger = this;
		this.setAttribute( 'aria-expanded', 'true' );
		modal.hidden = false;
		document.body.classList.add( 'abh-has-scan-summary-modal' );
		var closeButton = modal.querySelector( '.abh-scan-summary-close' );
		if ( closeButton ) { closeButton.focus(); }
	} );

	$( document ).on( 'click', '[data-abh-close-scan-summary]', closeScanSummary );

	$( document ).on( 'keydown', function ( event ) {
		var modal = document.getElementById( 'abh-scan-summary-modal' );
		if ( ! modal || modal.hidden ) { return; }
		if ( event.key === 'Escape' ) {
			event.preventDefault();
			closeScanSummary();
			return;
		}
		if ( event.key === 'Tab' ) {
			var focusable = Array.prototype.slice.call(
				modal.querySelectorAll( 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])' )
			);
			if ( ! focusable.length ) { return; }
			var first = focusable[0];
			var last = focusable[focusable.length - 1];
			if ( event.shiftKey && document.activeElement === first ) {
				event.preventDefault();
				last.focus();
			} else if ( ! event.shiftKey && document.activeElement === last ) {
				event.preventDefault();
				first.focus();
			}
		}
	} );


	/* ─────────────────────────────────────────────────────────────────────
	 * DINAMISMO — 1.5.2-alpha59
	 *
	 * Tres efectos, y ninguno inventa un dato: los números que suben son los
	 * mismos que ya venían pintados desde el servidor, las barras terminan en
	 * el ancho que ya traían, y el mini-gráfico ya está dibujado en el HTML —
	 * aquí solo se le anima el trazo. Si este archivo no cargara, la pantalla
	 * seguiría diciendo exactamente lo mismo, solo que quieta.
	 * ───────────────────────────────────────────────────────────────────── */
	var menosMovimiento = window.matchMedia &&
		window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;

	// El separador de miles se toma del texto que ya escribió PHP con
	// number_format_i18n, en vez de asumir el de un idioma concreto.
	function separador( $el, valor ) {
		var pintado = $.trim( $el.text() );
		var soloDigitos = pintado.replace( /[^0-9]/g, '' );
		if ( soloDigitos !== String( valor ) || pintado.length <= soloDigitos.length ) {
			return null;
		}
		var m = pintado.match( /[^0-9]/ );
		return m ? m[ 0 ] : null;
	}

	function agrupar( n, sep ) {
		var s = String( n );
		if ( ! sep ) { return s; }
		return s.replace( /\B(?=(\d{3})+(?!\d))/g, sep );
	}

	function contarHasta( $el ) {
		var destino = parseInt( $el.attr( 'data-abh-count' ), 10 );
		if ( isNaN( destino ) || destino <= 0 || menosMovimiento ) { return; }

		var sep = separador( $el, destino );
		var duracion = Math.min( 900, 260 + Math.log10( destino + 1 ) * 220 );
		var arranque = null;

		function paso( ahora ) {
			if ( null === arranque ) { arranque = ahora; }
			var t = Math.min( 1, ( ahora - arranque ) / duracion );
			// Desaceleración: el número frena al llegar en vez de cortarse en seco.
			var v = Math.round( destino * ( 1 - Math.pow( 1 - t, 3 ) ) );
			$el.text( agrupar( v, sep ) );
			if ( t < 1 ) { window.requestAnimationFrame( paso ); }
		}

		$el.text( agrupar( 0, sep ) );
		window.requestAnimationFrame( paso );
	}

	function animarBarras() {
		if ( menosMovimiento ) { return; }
		$( '.abh-consumo-barra > span' ).each( function () {
			var $s = $( this );
			var destino = this.style.width;
			if ( ! destino ) { return; }
			$s.addClass( 'is-animada' ).css( 'width', '0' );
			window.requestAnimationFrame( function () {
				window.requestAnimationFrame( function () { $s.css( 'width', destino ); } );
			} );
		} );
	}

	function animarSpark() {
		if ( menosMovimiento ) { return; }
		$( '.abh-consumo-spark' ).addClass( 'is-animado' );
	}

	/* ─────────────────────────────────────────────────────────────────────
	 * RADAR DE ESCANEO — alpha60
	 * Nace con el clic en «Scan now» y muere cuando el resultado nuevo
	 * llega (la tarjeta se vuelve a pintar o la página recarga). Muestra solo
	 * lo que sabe de verdad: que hay un escaneo en marcha y cuánto lleva.
	 * ───────────────────────────────────────────────────────────────────── */
	var radarTick = null;

	function pararRadar() {
		if ( radarTick ) { window.clearInterval( radarTick ); radarTick = null; }
		$( '.abh-fx-radar' ).remove();
		$( '.abh-scan-actions .button' ).prop( 'disabled', false );
	}

	$( document ).on( 'click', '.abh-syntax-scan', function () {
		var $card = $( this ).closest( '.abh-scan-card' );
		if ( ! $card.length || $card.find( '.abh-fx-radar' ).length ) { return; }
		var inicio = Date.now();
		var $radar = $(
			'<div class="abh-fx-radar" aria-live="polite">' +
				'<span class="abh-fx-radar-disco" aria-hidden="true"></span>' +
				'<span class="abh-fx-radar-texto"><strong>Scanning the site PHP files…</strong>' +
				'<span>The analysis runs on your server · <b>00:00</b></span></span>' +
			'</div>'
		);
		$card.find( '.abh-scan-head' ).after( $radar );
		var $resultado = $card.find( '.abh-scan-result' ).first();
		var firmaInicial = $resultado.text();
		radarTick = window.setInterval( function () {
			var t = Math.floor( ( Date.now() - inicio ) / 1000 );
			$radar.find( 'b' ).text(
				String( Math.floor( t / 60 ) ).padStart( 2, '0' ) + ':' + String( t % 60 ).padStart( 2, '0' )
			);
			// Si la tarjeta re-pintó su resultado (AJAX), el radar sobra. El tope
			// de 15 minutos es el cinturón por si el servidor nunca contesta.
			var $res = $( '.abh-scan-card .abh-scan-result' ).first();
			if ( ( $res.length && $res.text() !== firmaInicial ) || t > 900 ) { pararRadar(); }
		}, 500 );
	} );

	$( function () {
		organiseDashboardNotices();
		window.setTimeout( organiseDashboardNotices, 350 );
		$( '.abh-finding-workspace' ).each( function () { showFinding( $( this ), 0 ); } );
		$( '[data-abh-count]' ).each( function () { contarHasta( $( this ) ); } );
		animarBarras();
		animarSpark();
	} );
} )( jQuery );
