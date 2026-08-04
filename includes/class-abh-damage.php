<?php
/**
 * Censo del daño: ¿en cuántos sitios está roto este archivo, y tenemos el original?
 *
 * Por qué existe. En el banco de pruebas del dueño se rompió a mano una
 * plantilla de pago de WooCommerce en doce sitios distintos. HUNTER gastó 48.936
 * tokens, propuso UNA sola edición sobre la línea que el error mencionaba, y
 * después se bloqueó. Las tres cosas tienen la misma raíz: nadie contó el daño
 * antes de repararlo. El registro de PHP nombra el primer punto donde el
 * intérprete se rindió, no los once restantes; quien solo mira esa línea repara
 * una de doce y cree haber terminado.
 *
 * Contar es barato y no consume tokens. Y contar cambia la decisión:
 *
 *   stale_log → el archivo compila y es idéntico a su original publicado. Lo
 *               que hay en el registro es historia. No hay nada que reparar y
 *               no hay que preguntarle nada a ningún modelo.
 *   restore   → existe original publicado y difiere. La respuesta es el archivo
 *               entero, no un parche: copiar el original es certeza,
 *               reconstruirlo es apuesta.
 *   rewrite   → no hay original y el archivo no compila. Hay que reconstruir,
 *               y entonces el modelo tiene que enterarse de que el daño es
 *               múltiple ANTES de proponer nada.
 *   unknown   → ni una cosa ni la otra; sigue el flujo normal.
 *
 * Este archivo solo lee y compara. No escribe nada, nunca.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Mide cuánto daño tiene un archivo y cuánto cambiaría una reparación.
 *
 * POR QUE EXISTE:  Es lo que impide que un arreglo se coma medio archivo sin que nadie lo note.
 *
 * SI LO RECORTAS:  Sus topes son avisos con criterio, no vetos ciegos.
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
 * Class ABH_Damage
 */
class ABH_Damage {

	/**
	 * Máximo de líneas que se recorren buscando zonas sospechosas.
	 */
	const MAX_LINES = 6000;

	/**
	 * Censos ya calculados en esta misma petición.
	 *
	 * El censo se consulta desde tres sitios (el atajo determinista, la
	 * evidencia y el Fixer). Sin esta memoria, una misma reparación abriría el
	 * zip oficial tres veces y calcularía el diff completo tres veces.
	 *
	 * @var array
	 */
	private static $memo = array();

	/**
	 * Olvida lo calculado. Necesario en pruebas y tras escribir el archivo.
	 *
	 * @return void
	 */
	public static function flush_cache() {
		self::$memo = array();
	}

	/**
	 * Censo completo del daño de un archivo.
	 *
	 * @param string $rel Ruta relativa a ABSPATH.
	 * @return array
	 */
	public static function census( $rel ) {
		$rel = class_exists( 'ABH_Guard' ) ? ABH_Guard::normalize( $rel ) : (string) $rel;

		// La clave lleva la huella del CONTENIDO, no su fecha. Un archivo
		// reescrito dentro del mismo segundo y con el mismo tamaño tiene fecha y
		// tamaño idénticos: con esa clave se habría servido un censo viejo justo
		// en el caso que más importa, el de reparar y volver a comprobar.
		$firma = '';
		$abs   = defined( 'ABSPATH' ) ? ABSPATH . ltrim( (string) $rel, '/' ) : '';
		if ( '' !== $abs && @is_file( $abs ) ) {
			$h     = @md5_file( $abs );
			$firma = ( false === $h ) ? '' : (string) $h;
		}
		$clave = $rel . '|' . $firma;
		if ( ! isset( self::$memo[ $clave ] ) ) {
			self::$memo[ $clave ] = self::compute( $rel );
			// Techo de memoria: una petición no censa cien archivos distintos,
			// pero si ocurriera no se acumulan diffs completos sin límite.
			if ( count( self::$memo ) > 12 ) {
				array_shift( self::$memo );
			}
		}
		return self::$memo[ $clave ];
	}

	/**
	 * Cálculo real del censo, sin memoria.
	 *
	 * @param string $rel Ruta relativa ya normalizada.
	 * @return array
	 */
	private static function compute( $rel ) {
		$out = array(
			'rel_path'        => $rel,
			'exists'          => false,
			'parses'          => true,
			'parse_error'     => '',
			'parse_line'      => 0,
			'has_official'    => false,
			'confianza'       => '',
			'slug'            => '',
			'version'         => '',
			'official_sha256' => '',
			'disk_sha256'     => '',
			'hunks'           => 0,
			'changed_lines'   => 0,
			'diff'            => array(),
			'diff_truncado'   => false,
			'source_expected' => false,
			'verdict'         => 'unknown',
			'reason'          => '',
		);

		if ( '' === $rel ) {
			$out['reason'] = __( 'The issue does not point to any file.', 'ai-bug-hunter' );
			return $out;
		}

		$code = ABH_Engine::read_file( $rel );
		if ( false === $code ) {
			$out['reason'] = __( 'The file indicated cannot be read.', 'ai-bug-hunter' );
			return $out;
		}
		$out['exists']      = true;
		$out['disk_sha256'] = hash( 'sha256', $code );

		$lint = ABH_Verifier::lint( $code );
		if ( empty( $lint['ok'] ) ) {
			$out['parses']      = false;
			$out['parse_error'] = isset( $lint['detail'] ) ? (string) $lint['detail'] : '';
			if ( preg_match( '/l[ií]nea\s+(\d+)|line\s+(\d+)/i', $out['parse_error'], $m ) ) {
				$out['parse_line'] = (int) ( isset( $m[1] ) && '' !== $m[1] ? $m[1] : $m[2] );
			}
		}

		$oficial = class_exists( 'ABH_Source' ) ? ABH_Source::official_file( $rel ) : false;
		if ( is_array( $oficial ) && isset( $oficial['content'] ) ) {
			$out['has_official']    = true;
			$out['confianza']       = (string) $oficial['confianza'];
			$out['slug']            = isset( $oficial['origen']['slug'] ) ? (string) $oficial['origen']['slug'] : '';
			$out['version']         = isset( $oficial['origen']['version'] ) ? (string) $oficial['origen']['version'] : '';
			$out['official_sha256'] = hash( 'sha256', $oficial['content'] );

			if ( hash_equals( $out['official_sha256'], $out['disk_sha256'] ) ) {
				// Idéntico al original publicado. Si además compila, lo que hay
				// en el registro no describe el archivo que hay ahora en disco.
				$out['verdict'] = $out['parses'] ? 'stale_log' : 'unknown';
				$out['reason']  = $out['parses']
					? __( 'The file on disk is identical, byte for byte, to the original published by its developer, and compiles without errors. There is no evidence that this file is damaged or locally modified.', 'ai-bug-hunter' )
					: __( 'The file matches its published original but does not compile. Both cannot be true at once: it has to be checked again before touching anything.', 'ai-bug-hunter' );
				return $out;
			}

			// El diff SIEMPRE es del archivo completo: el daño no está donde el
			// error lo señala, está repartido, y solo se ve entero mirándolo entero.
			$out['diff'] = ABH_Engine::diff_rows( $oficial['content'], $code );
			$conteo      = self::count_diff( $out['diff'] );
			// El comparador visual se rinde con archivos muy grandes y devuelve
			// una única fila de aviso. Contar sobre ella daba «0 zonas» para un
			// archivo que sí difiere — las huellas ya habían demostrado que
			// difiere. Cuando eso pasa se cuenta a mano.
			if ( 0 === $conteo['hunks'] ) {
				$conteo               = self::count_positional( $oficial['content'], $code );
				$out['diff_truncado'] = true;
			}
			$out['hunks']         = $conteo['hunks'];
			$out['changed_lines'] = $conteo['lines'];
			$out['verdict']       = 'restore';
			$out['reason']        = sprintf(
				/* translators: 1: zonas, 2: líneas, 3: slug, 4: versión. */
				_n(
					'Your copy differs from the original %3$s %4$s in %1$d area (%2$d lines).',
					'Your copy differs from the original %3$s %4$s in %1$d separate areas (%2$d lines).',
					$conteo['hunks'],
					'ai-bug-hunter'
				),
				$conteo['hunks'],
				$conteo['lines'],
				$out['slug'],
				$out['version']
			);
			return $out;
		}

		// Aquí no se ha podido usar un original. Hay dos motivos muy distintos y
		// confundirlos cambia la reparación: que este archivo NO tenga original
		// publicado (código propio, plugin de pago), o que sí lo tenga y esta vez
		// no se haya podido traer —sin red, el zip no cuadró con su manifiesto—.
		// En el segundo caso reconstruir con IA sería peor que esperar: la
		// respuesta correcta sigue siendo restaurar, y hay que decir eso.
		if ( class_exists( 'ABH_Source' ) && method_exists( 'ABH_Source', 'identify' ) ) {
			$id = ABH_Source::identify( $rel );
			if ( ! empty( $id['verifiable'] ) ) {
				$out['source_expected'] = true;
				$out['slug']            = (string) $id['slug'];
				$out['version']         = (string) $id['version'];
				$out['verdict']         = 'unknown';
				$out['reason']          = sprintf(
					/* translators: 1: slug, 2: versión. */
					__( '%1$s %2$s does publish an original of this file, but this time it could not be fetched for comparison. It is not that it does not exist: it did not arrive. Try again before reconstructing anything, because restoring the original is safer than deducing it.', 'ai-bug-hunter' ),
					$id['slug'],
					$id['version']
				);
				return $out;
			}
		}

		// Sin original publicado. Si no compila hay que reconstruir, y entonces
		// importa cuántas zonas sospechosas hay, no solo la que PHP nombró.
		if ( ! $out['parses'] ) {
			$out['hunks']   = self::heuristic_hunks( $code );
			$out['verdict'] = 'rewrite';
			// «Al menos», no «exactamente»: sin original con el que comparar,
			// solo se ve el daño que rompe la sintaxis. Un identificador mal
			// escrito compila igual y no hay forma de contarlo sin el original.
			$out['reason'] = $out['hunks'] > 1
				? sprintf(
					/* translators: %d: zonas sospechosas. */
					__( 'There is no published original to compare against. The file does not compile and at least %d suspicious areas were detected: the log error only names the first one.', 'ai-bug-hunter' ),
					$out['hunks']
				)
				: __( 'There is no published original to compare against and the file does not compile. Without an original, only the damage that breaks the syntax can be seen: a misspelled name compiles all the same and there is no way to detect it by comparing the file with itself.', 'ai-bug-hunter' );
			return $out;
		}

		$out['reason'] = __( 'The file compiles and there is no published original to compare it with.', 'ai-bug-hunter' );
		return $out;
	}

	/**
	 * Zonas y líneas cambiadas de un diff.
	 *
	 * Una «zona» es un bloque contiguo de líneas distintas. Doce erratas
	 * repartidas por el archivo dan doce zonas; una sola línea mal escrita da
	 * una. Es la cifra que le dice a una persona si esto es una errata o un
	 * archivo destrozado.
	 *
	 * @param array $rows Filas de ABH_Engine::diff_rows().
	 * @return array hunks, lines
	 */
	public static function count_diff( $rows ) {
		$hunks  = 0;
		$lines  = 0;
		$dentro = false;
		foreach ( (array) $rows as $row ) {
			$tipo = isset( $row['type'] ) ? (string) $row['type'] : '';
			if ( 'add' !== $tipo && 'del' !== $tipo ) {
				$dentro = false;
				continue;
			}
			$lines++;
			if ( ! $dentro ) {
				$hunks++;
				$dentro = true;
			}
		}
		return array( 'hunks' => $hunks, 'lines' => $lines );
	}

	/**
	 * Cuenta zonas comparando línea a línea, sin subsecuencia común.
	 *
	 * Existe porque el comparador visual se rinde con los archivos grandes y
	 * devuelve una sola fila explicativa. Contar sobre esa fila daba cero, y
	 * cero se lee como «no hay diferencias» justo en el archivo donde más
	 * importa que las haya. Este recuento es más tosco —una línea insertada
	 * desplaza el resto— pero nunca dice cero cuando los archivos difieren.
	 *
	 * @param string $a Original.
	 * @param string $b Copia instalada.
	 * @return array hunks, lines
	 */
	public static function count_positional( $a, $b ) {
		$x = preg_split( '/\r\n|\r|\n/', (string) $a );
		$y = preg_split( '/\r\n|\r|\n/', (string) $b );
		$n = max( count( $x ), count( $y ) );

		$hunks  = 0;
		$lines  = 0;
		$dentro = false;
		for ( $i = 0; $i < $n; $i++ ) {
			$ai = isset( $x[ $i ] ) ? $x[ $i ] : null;
			$bi = isset( $y[ $i ] ) ? $y[ $i ] : null;
			if ( $ai === $bi ) {
				$dentro = false;
				continue;
			}
			$lines++;
			if ( ! $dentro ) {
				$hunks++;
				$dentro = true;
			}
		}
		return array( 'hunks' => $hunks, 'lines' => $lines );
	}

	/**
	 * Cuenta zonas sospechosas cuando no hay original con el que comparar.
	 *
	 * No pretende ser un compilador: pretende evitar que un archivo roto en
	 * doce sitios se presente como una errata de una línea. Las líneas seguidas
	 * cuentan como una sola zona.
	 *
	 * @param string $code Contenido.
	 * @return int
	 */
	public static function heuristic_hunks( $code ) {
		$code = (string) $code;
		if ( '' === trim( $code ) || ! function_exists( 'token_get_all' ) ) {
			return 0;
		}

		// Se tokeniza SIN TOKEN_PARSE: así el analizador léxico no se detiene en
		// el primer error de sintaxis y se puede recorrer el archivo entero.
		// Contar a base de expresiones regulares por línea no funcionaba: en el
		// estilo de WordPress una llamada repartida en varias líneas termina en
		// «);», y cualquier regla basada en «paréntesis descuadrados + punto y
		// coma» marcaba como daño el código correcto del propio plugin. Con
		// tokens, las cadenas y los comentarios dejan de contar, y la
		// profundidad de paréntesis es la de verdad, no la de una sola línea.
		$tokens = @token_get_all( $code );
		if ( ! is_array( $tokens ) || ! $tokens ) {
			return 0;
		}

		// Pila unificada de delimitadores abiertos. Un «;» solo es sospechoso
		// cuando lo más cercano que hay abierto es un paréntesis de llamada:
		//   · dentro de un for(;;) los «;» son sintaxis, no error;
		//   · dentro del cuerpo { } de una función anónima pasada como argumento
		//     los «;» también son legítimos, aunque haya un paréntesis abierto
		//     más abajo en la pila.
		// Ambos casos abundan en el propio plugin y en el núcleo de WordPress;
		// sin distinguirlos, el contador marcaba como daño el código correcto.
		$pila         = array();
		$hunks        = 0;
		$ultima_linea = -10; // Zonas contiguas cuentan como una sola.
		$linea_actual = 1;
		$anterior     = null; // Último token significativo.
		$es_for       = false;
		$sin_espacio  = true;  // ¿El token anterior estaba pegado a este?
		$total        = count( $tokens );

		for ( $i = 0; $i < $total; $i++ ) {
			$tk = $tokens[ $i ];

			if ( is_array( $tk ) ) {
				$linea_actual = (int) $tk[2];
				if ( T_WHITESPACE === $tk[0] || T_COMMENT === $tk[0] || T_DOC_COMMENT === $tk[0] ) {
					// Se recuerda si hubo separación real entre dos tokens: es
					// lo que distingue «foo(); asd» de «foo();asd».
					$sin_espacio = false;
					continue;
				}

				$pegado = false;

				// Texto suelto pegado justo detrás de un «;», en la MISMA línea:
				// «render( $g );asd». Si el bloque PHP se cerró, el analizador lo
				// devuelve como HTML en línea; si no, como un identificador
				// suelto. Los dos casos son la misma firma de pegado accidental,
				// y en código legítimo nunca hay nada pegado a un punto y coma
				// sin al menos un espacio o un salto de línea.
				if ( ';' === $anterior && $sin_espacio
					&& ( T_INLINE_HTML === $tk[0] || T_STRING === $tk[0] )
					&& '' !== trim( (string) $tk[1] )
					&& false === strpos( (string) $tk[1], "\n" ) ) {
					$pegado = true;
				}

				// Un identificador seguido directamente de una cadena literal
				// —«apply_fasd 'acme_no_methods_message'»— no es PHP válido en
				// ningún contexto: entre los dos falta lo que el daño se comió.
				//
				// Solo cadenas. Un identificador seguido de una VARIABLE sí es
				// válido y abunda: «catch ( Exception $e )», «function f( Foo $x )».
				// Incluirlo marcaba como daño la mitad de los archivos sanos.
				if ( T_STRING === $anterior && T_CONSTANT_ENCAPSED_STRING === $tk[0] ) {
					$pegado = true;
				}

				if ( $pegado ) {
					if ( $linea_actual - $ultima_linea > 1 ) {
						$hunks++;
					}
					$ultima_linea = $linea_actual;
				}

				$es_for      = ( T_FOR === $tk[0] );
				$anterior    = $tk[0];
				$sin_espacio = true;
				continue;
			}

			if ( '(' === $tk ) {
				$pila[] = $es_for ? 'for' : '(';
				$es_for = false;
			} elseif ( '{' === $tk ) {
				$pila[] = '{';
			} elseif ( '[' === $tk ) {
				$pila[] = '[';
			} elseif ( ')' === $tk || '}' === $tk || ']' === $tk ) {
				array_pop( $pila );
			} elseif ( ';' === $tk && ! empty( $pila ) && '(' === end( $pila ) ) {
				// Una sentencia no puede terminar dentro de una llamada abierta.
				// Aquí sí es daño: falta un cierre, y falta en este punto.
				if ( $linea_actual - $ultima_linea > 1 ) {
					$hunks++;
				}
				$ultima_linea = $linea_actual;
				$pila         = array(); // Se reencuadra para no arrastrar el desfase.
			}
			if ( '(' !== $tk ) {
				$es_for = false;
			}
			$anterior    = $tk;
			$sin_espacio = true;
		}

		// Si al final del archivo queda una llamada abierta, falta un cierre que
		// no se ha contado en ningún punto anterior. Las llaves sin cerrar no se
		// cuentan aquí: en una plantilla con HTML intercalado son normales al
		// terminar el bloque PHP.
		if ( in_array( '(', $pila, true ) && $linea_actual - $ultima_linea > 1 ) {
			$hunks++;
		}

		return $hunks;
	}

	/**
	 * Frase corta para la consola y el reporte.
	 *
	 * @param array $censo Resultado de census().
	 * @return string
	 */
	public static function headline( $censo ) {
		$verdict = isset( $censo['verdict'] ) ? $censo['verdict'] : '';
		$hunks   = isset( $censo['hunks'] ) ? (int) $censo['hunks'] : 0;

		if ( 'stale_log' === $verdict ) {
			return __( 'There is nothing to repair: the file is intact.', 'ai-bug-hunter' );
		}
		if ( 'restore' === $verdict ) {
			return sprintf(
				/* translators: %d: zonas dañadas. */
				_n( 'The file differs from its original in %d area.', 'The file differs from its original in %d areas.', $hunks, 'ai-bug-hunter' ),
				$hunks
			);
		}
		if ( 'rewrite' === $verdict ) {
			return $hunks > 1
				? sprintf(
					/* translators: %d: zonas sospechosas. */
					__( 'The file does not compile and there are at least %d suspicious areas, not one.', 'ai-bug-hunter' ),
					$hunks
				)
				: __( 'The file does not compile.', 'ai-bug-hunter' );
		}
		return '';
	}
}
