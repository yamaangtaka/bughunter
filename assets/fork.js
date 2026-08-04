/**
 * El diálogo de bifurcación: «te digo qué hacer» o «lo hago yo».
 *
 * Vive aparte de admin.js a propósito. Ese archivo guarda todo el estado de la
 * reparación en un objeto de cierre de 39 claves referenciado 241 veces, y no
 * exporta nada al exterior; añadirle una pieza es exactamente el cambio que
 * rompe la consola de una forma que no se ve hasta que alguien aplica un parche
 * en un sitio de verdad.
 *
 * Aquí no hay estado ni dependencias. Se abre, devuelve la elección por
 * callback, y se cierra.
 *
 *   ABHFork.open({
 *     onReading: function () { ... },
 *     onRepair:  function () { ... },
 *     onCancel:  function () { ... }
 *   });
 *
 * Ningún precio se escribe en este archivo: llegan ya formateados desde el
 * servidor, y cuando no se conoce uno llega cadena vacía. Un botón sin cifra es
 * honesto; un «$0.00» inventado no lo es.
 */
(function () {
	'use strict';

	var cfg = window.ABHFORK || {};
	var box = null;
	var pending = null;
	var lastFocus = null;

	function $(sel) {
		return box ? box.querySelector(sel) : null;
	}

	function label(base, price, free) {
		if (free) {
			return base + ' · ' + (cfg.labels && cfg.labels.free ? cfg.labels.free : '');
		}
		return price ? base + ' · ' + price : base;
	}

	function resolve(fn) {
		var p = pending;
		close();
		pending = null;
		if (p && p[fn]) { p[fn](); }
	}

	function onKey(e) {
		if (e.key === 'Escape') {
			resolve('onCancel');
			return;
		}
		if (e.key !== 'Tab' || !box) { return; }
		// Un diálogo modal que deja escapar el foco al fondo no es modal.
		var focusable = box.querySelectorAll('button:not([disabled])');
		if (!focusable.length) { return; }
		var first = focusable[0];
		var last = focusable[focusable.length - 1];
		if (e.shiftKey && document.activeElement === first) {
			e.preventDefault();
			last.focus();
		} else if (!e.shiftKey && document.activeElement === last) {
			e.preventDefault();
			first.focus();
		}
	}

	function close() {
		if (!box) { return; }
		box.hidden = true;
		document.removeEventListener('keydown', onKey, true);
		if (lastFocus && lastFocus.focus) { lastFocus.focus(); }
		lastFocus = null;
	}

	function open(opts) {
		box = document.getElementById('abh-fork');
		if (!box) {
			// Sin diálogo no se bloquea al usuario: se sigue por la lectura, que
			// es la rama barata y la que no escribe nada.
			if (opts && opts.onReading) { opts.onReading(); }
			return;
		}

		pending = opts || {};
		lastFocus = document.activeElement;

		var L = cfg.labels || {};
		var P = cfg.prices || {};
		var F = cfg.freeNow || {};

		$('.abh-fork-titulo').textContent = L.title || '';
		$('.abh-fork-explica').textContent = L.explain || '';
		$('.abh-fork-cancelar').textContent = L.cancel || '';

		var bRead = $('.abh-fork-lectura');
		var bRep = $('.abh-fork-reparacion');
		bRead.textContent = label(L.reading || '', P.reading, F.reading);
		bRep.textContent = label(L.repair || '', P.repair, F.repair);

		box.hidden = false;
		document.addEventListener('keydown', onKey, true);
		bRead.focus();
	}

	function wire() {
		box = document.getElementById('abh-fork');
		if (!box) { return; }

		box.addEventListener('click', function (e) {
			var t = e.target;
			// Un clic en el fondo cancela, igual que Escape.
			if (t === box || t.classList.contains('abh-fork-cancelar')) {
				resolve('onCancel');
			} else if (t.classList.contains('abh-fork-lectura')) {
				resolve('onReading');
			} else if (t.classList.contains('abh-fork-reparacion')) {
				resolve('onRepair');
			}
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', wire);
	} else {
		wire();
	}

	window.ABHFork = { open: open, close: close };
})();
