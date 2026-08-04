<?php
/**
 * Recolector determinista de evidencia para HUNTER AI.
 *
 * Inspecciona el código desplegado antes de que el Referee emita un veredicto:
 * definiciones, llamadas, visibilidad, archivos duplicados, versión y hashes.
 * No ejecuta el proyecto y no envía código fuente completo al proveedor de IA.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Extrae evidencia estructural del código sin gastar un solo token.
 *
 * POR QUE EXISTE:  Es la parte determinista: lo que se puede saber sin preguntarle a nadie.
 *
 * SI LO RECORTAS:  Cuanto más resuelve esto, menos hace falta la IA. Recortarlo no ahorra riesgo: lo traslada al modelo.
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
 * Class ABH_Evidence
 */
class ABH_Evidence {

	const MAX_FILES = 600;
	const MAX_BYTES = 1572864;

	/**
	 * Recopila evidencia relacionada con una incidencia.
	 *
	 * @param array $job Trabajo HUNTER AI.
	 * @return array
	 */
	/**
	 * Hechos comprobables sobre el archivo del incidente.
	 *
	 * Todo lo que aquí se devuelve es medible: una huella, una fecha del sistema
	 * de ficheros, el veredicto del compilador y la comparación con el original
	 * publicado. Nada es opinión, así que el árbitro no tiene que fiarse de
	 * nadie para usarlo.
	 *
	 * @param string $rel Ruta relativa del archivo.
	 * @return array
	 */
	public static function subject( $rel ) {
		$out = array(
			'rel_path'       => $rel,
			'exists'         => false,
			'sha256'         => '',
			'bytes'          => 0,
			'modified'       => 0,
			'modified_human' => '',
			'parses'         => true,
			'parse_error'    => '',
			'parse_line'     => 0,
			'broken_region'  => array(),
			'origin'         => array( 'known' => false, 'altered' => false, 'confianza' => '', 'slug' => '', 'version' => '', 'reason' => '' ),
		);

		$code = ABH_Engine::read_file( $rel );
		if ( false === $code ) {
			return $out;
		}
		$out['exists'] = true;
		$out['sha256'] = hash( 'sha256', $code );
		$out['bytes']  = strlen( $code );

		$abs = ABSPATH . ltrim( $rel, '/' );
		$mt  = @filemtime( $abs );
		if ( $mt ) {
			$out['modified']       = (int) $mt;
			$out['modified_human'] = gmdate( 'Y-m-d H:i:s', (int) $mt ) . ' UTC';
		}

		$lint = ABH_Verifier::lint( $code );
		if ( empty( $lint['ok'] ) ) {
			$out['parses']      = false;
			$out['parse_error'] = isset( $lint['detail'] ) ? (string) $lint['detail'] : '';
			if ( preg_match( '/l[ií]nea\s+(\d+)|line\s+(\d+)/i', $out['parse_error'], $m ) ) {
				$out['parse_line'] = (int) ( '' !== $m[1] ? $m[1] : $m[2] );
			}
			$out['broken_region'] = self::region( $code, $out['parse_line'] );
		}

		if ( class_exists( 'ABH_Damage' ) ) {
			// El censo compara y CUENTA. Antes esto era un booleano y el reporte
			// se limitaba a decir «coincide» o «DIFIERE»; el Skeptic respondía,
			// con razón, que no había prueba de que el archivo en disco fuera el
			// del manifiesto. Ahora van las dos huellas y el número de zonas: ya
			// no es un veredicto que haya que creerse, es una comparación que
			// cualquiera puede repetir.
			$censo         = ABH_Damage::census( $rel );
			$out['origin'] = array(
				'known'           => ! empty( $censo['has_official'] ),
				'altered'         => ( 'restore' === $censo['verdict'] ),
				'confianza'       => (string) $censo['confianza'],
				'slug'            => (string) $censo['slug'],
				'version'         => (string) $censo['version'],
				'reason'          => (string) $censo['reason'],
				'official_sha256' => (string) $censo['official_sha256'],
				'hunks'           => (int) $censo['hunks'],
				'changed_lines'   => (int) $censo['changed_lines'],
				'verdict'         => (string) $censo['verdict'],
				// Un original publicado compila. Si el archivo coincide con él y
				// aun así no compila, una de las dos medidas está mal, y hay que
				// decirlo en vez de quedarse con la que convenga.
				'contradiction'   => ( ! empty( $censo['has_official'] ) && empty( $censo['parses'] )
					&& '' !== $censo['official_sha256'] && $censo['official_sha256'] === $censo['disk_sha256'] ),
			);
		} elseif ( class_exists( 'ABH_Source' ) ) {
			$st            = ABH_Source::status( $rel );
			$out['origin'] = array(
				'known'     => ! empty( $st['known'] ),
				'altered'   => ! empty( $st['altered'] ),
				'confianza' => (string) $st['confianza'],
				'slug'      => (string) $st['slug'],
				'version'   => (string) $st['version'],
				'reason'    => (string) $st['reason'],
			);
		}
		return $out;
	}

	/**
	 * Líneas alrededor del punto donde PHP se rindió.
	 *
	 * El número de línea que reporta el compilador es donde se dio cuenta, no
	 * siempre donde está el daño, así que se devuelve un entorno amplio.
	 *
	 * @param string $code  Contenido.
	 * @param int    $linea Línea reportada.
	 * @return array
	 */
	private static function region( $code, $linea ) {
		$lineas = preg_split( '/\r\n|\r|\n/', $code );
		$total  = count( $lineas );
		if ( $total < 1 ) {
			return array();
		}
		$linea  = ( $linea > 0 && $linea <= $total ) ? $linea : $total;
		$desde  = max( 1, $linea - 25 );
		$hasta  = min( $total, $linea + 8 );
		$region = array();
		for ( $i = $desde; $i <= $hasta; $i++ ) {
			$texto = isset( $lineas[ $i - 1 ] ) ? $lineas[ $i - 1 ] : '';
			$region[] = array(
				'line'     => $i,
				'text'     => function_exists( 'mb_substr' ) ? mb_substr( $texto, 0, 300 ) : substr( $texto, 0, 300 ),
				'reported' => ( $i === $linea ),
			);
		}
		return $region;
	}

	public static function collect( $job ) {
		$rel = isset( $job['incident']['rel_path'] ) ? ABH_Guard::normalize( $job['incident']['rel_path'] ) : '';
		if ( '' === $rel ) {
			return array( 'ok' => false, 'message' => __( 'The issue has no valid path for collecting evidence.', 'ai-bug-hunter' ) );
		}

		$root = self::project_root( $rel );
		if ( empty( $root['abs'] ) || ! is_dir( $root['abs'] ) ) {
			return array( 'ok' => false, 'message' => __( 'I could not identify the project that contains the affected file.', 'ai-bug-hunter' ) );
		}

		// El archivo del incidente, mirado de frente. En el benchmark del dueño
		// el Referee bloqueó pidiendo «el hash SHA256 del archivo problemático»
		// y «logs de modificación» — datos que estaban a mano pero enterrados
		// entre 600 archivos de símbolos. Ahora van en su propio bloque.
		$subject = self::subject( $rel );

		$wanted = self::wanted_symbols( $job );

		// PHP ya sabe de dónde cargó la clase. Si el símbolo vive en OTRA
		// carpeta —una copia vieja del mismo plugin, el caso clásico de
		// «Cannot declare class ... already in use»— esa carpeta también entra.
		//
		// Sin esto el recolector se ancla a la carpeta del archivo del incidente
		// y nunca abre la segunda: la sonda de runtime reportaba una ruta que la
		// evidencia estática no había visto jamás, el árbitro veía una
		// contradicción REAL y el caso moría en revisión manual. No era un
		// permiso ni un endurecimiento: era una carpeta que nadie miró.
		$roots = array( $root['abs'] );
		foreach ( self::runtime_roots( $wanted ) as $extra ) {
			if ( ! in_array( $extra, $roots, true ) ) {
				$roots[] = $extra;
			}
		}

		// Un archivo que no compila no tiene símbolos que recorrer: barrer el
		// proyecto entero devolvería ruido y ocultaría lo único que importa,
		// que son las líneas rotas.
		$files = array();
		if ( ! empty( $subject['parses'] ) ) {
			foreach ( $roots as $uno ) {
				$files = array_merge( $files, self::php_files( $uno ) );
			}
			$files = array_values( array_unique( $files ) );
		}
		$definitions = array();
		$calls       = array();
		$file_hashes = array();
		$skipped     = array();

		foreach ( $files as $abs ) {
			$size = @filesize( $abs );
			if ( false === $size || $size > self::MAX_BYTES || is_link( $abs ) ) {
				$skipped[] = self::relative( $abs );
				continue;
			}
			$code = @file_get_contents( $abs );
			if ( false === $code ) {
				$skipped[] = self::relative( $abs );
				continue;
			}
			$relative = self::relative( $abs );
			$file_hashes[ $relative ] = hash( 'sha256', $code );
			$parsed = self::parse_php( $code, $relative );
			$definitions = array_merge( $definitions, $parsed['definitions'] );
			$calls       = array_merge( $calls, $parsed['calls'] );
		}

		$matched_definitions = self::filter_definitions( $definitions, $wanted );
		$matched_calls       = self::filter_calls( $calls, $wanted );
		$duplicates          = self::duplicates( $definitions, $wanted );
		$alternatives        = self::alternatives( $definitions, $wanted );
		$version             = self::project_version( $root['abs'] );
		$target_hash         = isset( $file_hashes[ $rel ] ) ? $file_hashes[ $rel ] : '';
		$runtime             = self::runtime_evidence( $wanted, $matched_definitions, $file_hashes );

		$summary = array();
		if ( ! empty( $subject['exists'] ) ) {
			$summary[] = sprintf(
				/* translators: 1: ruta, 2: huella corta. */
				__( 'SHA-256 fingerprint of the incident file (%1$s): %2$s.', 'ai-bug-hunter' ),
				$rel,
				substr( $subject['sha256'], 0, 32 ) . '…'
			);
			if ( ! empty( $subject['modified_human'] ) ) {
				$summary[] = sprintf(
					/* translators: %s: fecha de última modificación. */
					__( 'Last modification of the file according to the file system: %s.', 'ai-bug-hunter' ),
					$subject['modified_human']
				);
			}
			if ( empty( $subject['parses'] ) ) {
				$summary[] = sprintf(
					/* translators: %s: detalle del error de sintaxis. */
					__( 'The file does NOT compile: %s. That is why there are no symbols to inventory; what matters are the broken lines, included below.', 'ai-bug-hunter' ),
					$subject['parse_error']
				);
			}
			if ( ! empty( $subject['origin']['known'] ) ) {
				// Las dos huellas van escritas. Decir solo «coincide» obligaba a
				// creerse el veredicto, y el Skeptic contestaba —con razón— que
				// no había prueba de que el archivo en disco fuera el publicado.
				$summary[] = sprintf(
					/* translators: 1: slug, 2: versión, 3: nivel de verificación, 4: huella en disco, 5: huella del original. */
					__( 'Published original of %1$s %2$s located (verification: %3$s). Fingerprint of the file on disk: %4$s. Fingerprint of the original: %5$s.', 'ai-bug-hunter' ),
					$subject['origin']['slug'],
					$subject['origin']['version'],
					$subject['origin']['confianza'],
					substr( (string) $subject['sha256'], 0, 32 ) . '…',
					substr( (string) $subject['origin']['official_sha256'], 0, 32 ) . '…'
				);
				if ( ! empty( $subject['origin']['altered'] ) ) {
					$summary[] = sprintf(
						/* translators: 1: zonas, 2: líneas. */
						_n(
							'The fingerprints DO NOT match: your copy differs from the original in %1$d area (%2$d lines).',
							'The fingerprints DO NOT match: your copy differs from the original in %1$d separate areas (%2$d lines). The logged error identifies only one of them.',
							(int) $subject['origin']['hunks'],
							'ai-bug-hunter'
						),
						(int) $subject['origin']['hunks'],
						(int) $subject['origin']['changed_lines']
					);
				} elseif ( ! empty( $subject['origin']['contradiction'] ) ) {
					$summary[] = __( 'CONTRADICTION: the fingerprints match but the file does not compile, and a published original does compile. Do not treat either measurement as reliable: the file has to be read again before proposing anything.', 'ai-bug-hunter' );
				} else {
					$summary[] = __( 'The fingerprints match byte for byte: the deployed file is the developer\'s published original. The log may describe an earlier runtime state, intentional upstream behavior, or a failure originating elsewhere.', 'ai-bug-hunter' );
				}
			} elseif ( '' !== (string) $subject['origin']['reason'] ) {
				$summary[] = sprintf(
					/* translators: %s: motivo. */
					__( 'There is no official original to compare this file against: %s', 'ai-bug-hunter' ),
					$subject['origin']['reason']
				);
			}
		}
		$summary[] = sprintf(
			/* translators: 1: files scanned, 2: definitions, 3: calls. */
			__( 'I reviewed %1$d PHP files, %2$d related definitions and %3$d related calls.', 'ai-bug-hunter' ),
			count( $file_hashes ),
			count( $matched_definitions ),
			count( $matched_calls )
		);
		if ( '' !== $version ) {
			$summary[] = sprintf( /* translators: %s: project version declared in its metadata. */ __( 'The project\'s declared version is %s.', 'ai-bug-hunter' ), $version );
		}
		if ( $duplicates ) {
			$summary[] = __( 'I found duplicate definitions that must be ruled out before choosing a repair.', 'ai-bug-hunter' );
		} else {
			$summary[] = __( 'I did not find duplicate definitions of the symbols investigated.', 'ai-bug-hunter' );
		}
		if ( $matched_definitions ) {
			$summary[] = __( 'The actual declaration and its visibility were verified directly in the deployed code.', 'ai-bug-hunter' );
		}
		if ( ! empty( $runtime['summary'] ) ) {
			$summary = array_merge( $summary, $runtime['summary'] );
		}

		return array(
			'ok'             => true,
			'collector'      => 'thoth-evidence/1',
			'collected_at'   => time(),
			'project_root'   => $root['rel'],
			'project_version'=> $version,
			'target_file'    => $rel,
			'target_sha256'  => '' !== $target_hash ? $target_hash : $subject['sha256'],
			'subject'        => $subject,
			'files_scanned'  => count( $file_hashes ),
			'files_skipped'  => array_slice( $skipped, 0, 30 ),
			'wanted_symbols' => $wanted,
			'definitions'    => array_slice( $matched_definitions, 0, 40 ),
			'calls'          => array_slice( $matched_calls, 0, 50 ),
			'duplicates'     => array_slice( $duplicates, 0, 20 ),
			'public_alternatives' => array_slice( $alternatives, 0, 20 ),
			'relevant_hashes'=> self::relevant_hashes( $file_hashes, $matched_definitions, $matched_calls, $rel ),
			'runtime'        => $runtime,
			'summary'        => $summary,
		);
	}

	/**
	 * Identifica la raíz del plugin o tema sin crear excepciones por nombre.
	 *
	 * @param string $rel Ruta relativa.
	 * @return array
	 */
	private static function project_root( $rel ) {
		$parts = explode( '/', trim( $rel, '/' ) );
		$root_rel = dirname( $rel );
		if ( count( $parts ) >= 3 && 'wp-content' === $parts[0] && in_array( $parts[1], array( 'plugins', 'themes' ), true ) ) {
			$root_rel = implode( '/', array_slice( $parts, 0, 3 ) );
		} elseif ( count( $parts ) >= 2 && 'wp-content' === $parts[0] && 'mu-plugins' === $parts[1] ) {
			$root_rel = 'wp-content/mu-plugins';
		}
		$root_rel = ABH_Guard::normalize( $root_rel );
		$abs = wp_normalize_path( ABSPATH . ltrim( $root_rel, '/' ) );
		$real = realpath( $abs );
		$base = realpath( ABSPATH );
		if ( false === $real || false === $base ) {
			return array();
		}
		$real = wp_normalize_path( $real );
		$base = trailingslashit( wp_normalize_path( $base ) );
		if ( 0 !== strpos( trailingslashit( $real ), $base ) ) {
			return array();
		}
		return array( 'rel' => $root_rel, 'abs' => $real );
	}

	/**
	 * Lista archivos PHP de forma acotada y sin seguir enlaces.
	 *
	 * @param string $root Raíz absoluta.
	 * @return array
	 */
	/**
	 * Carpetas extra que delata el propio PHP.
	 *
	 * Para cada símbolo investigado que YA esté cargado en esta petición,
	 * Reflection dice en qué archivo se declaró. Si ese archivo cae fuera de la
	 * carpeta del incidente, su proyecto entra a la evidencia. Es determinista,
	 * no gasta tokens y es justo el dato que faltaba cuando la misma clase vive
	 * en dos carpetas distintas.
	 *
	 * @param array $wanted Símbolos investigados.
	 * @return array Rutas absolutas de carpetas.
	 */
	private static function runtime_roots( $wanted ) {
		$out = array();
		if ( empty( $wanted['classes'] ) || ! is_array( $wanted['classes'] ) ) {
			return $out;
		}
		foreach ( $wanted['classes'] as $clase ) {
			$clase = (string) $clase;
			if ( '' === $clase || ! class_exists( $clase, false ) ) {
				continue;
			}
			try {
				$ref     = new ReflectionClass( $clase );
				$archivo = $ref->getFileName();
			} catch ( Exception $e ) {
				continue;
			} catch ( Error $e ) {
				continue;
			}
			if ( ! $archivo ) {
				continue;
			}
			$rel  = ABH_Guard::normalize( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $archivo ) ) );
			$raiz = self::project_root( $rel );
			if ( ! empty( $raiz['abs'] ) && is_dir( $raiz['abs'] ) ) {
				$out[] = $raiz['abs'];
			}
		}
		return array_values( array_unique( $out ) );
	}

	private static function php_files( $root ) {
		$out = array();
		$flags = FilesystemIterator::SKIP_DOTS;
		try {
			$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, $flags ) );
			foreach ( $it as $file ) {
				if ( count( $out ) >= self::MAX_FILES ) {
					break;
				}
				if ( $file->isLink() || ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
					continue;
				}
				$out[] = wp_normalize_path( $file->getPathname() );
			}
		} catch ( Exception $e ) {
			return $out;
		}
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * Extrae clases, métodos y llamadas mediante tokens reales de PHP.
	 *
	 * @param string $code Código.
	 * @param string $file Ruta relativa.
	 * @return array
	 */
	private static function parse_php( $code, $file ) {
		$tokens = token_get_all( $code );
		$definitions = array();
		$calls = array();
		$current_class = '';
		$class_depth = null;
		$depth = 0;
		$pending_class = '';
		$visibility = 'public';
		$count = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$t = $tokens[ $i ];
			if ( '{' === $t ) {
				$depth++;
				if ( '' !== $pending_class ) {
					$current_class = $pending_class;
					$class_depth = $depth;
					$pending_class = '';
				}
				continue;
			}
			if ( ';' === $t ) {
				$visibility = 'public';
				continue;
			}
			if ( '}' === $t ) {
				if ( null !== $class_depth && $depth === $class_depth ) {
					$current_class = '';
					$class_depth = null;
				}
				$depth = max( 0, $depth - 1 );
				continue;
			}
			if ( ! is_array( $t ) ) {
				continue;
			}
			$id = $t[0];
			$text = $t[1];
			$line = isset( $t[2] ) ? (int) $t[2] : 0;

			if ( in_array( $id, array( T_PUBLIC, T_PROTECTED, T_PRIVATE ), true ) ) {
				$visibility = strtolower( trim( $text ) );
				continue;
			}
			if ( T_CLASS === $id || T_INTERFACE === $id || T_TRAIT === $id ) {
				$name = self::next_string( $tokens, $i + 1 );
				if ( '' !== $name ) {
					$definitions[] = array( 'type' => 'class', 'class' => $name, 'name' => $name, 'visibility' => 'public', 'file' => $file, 'line' => $line );
					$pending_class = $name;
				}
				continue;
			}
			if ( T_FUNCTION === $id ) {
				$name = self::next_string( $tokens, $i + 1 );
				if ( '' !== $name ) {
					$definitions[] = array(
						'type'       => '' !== $current_class ? 'method' : 'function',
						'class'      => $current_class,
						'name'       => $name,
						'visibility' => '' !== $current_class ? $visibility : 'public',
						'file'       => $file,
						'line'       => $line,
					);
				}
				$visibility = 'public';
				continue;
			}
			if ( T_STRING === $id && self::next_non_whitespace_is( $tokens, $i + 1, '(' ) ) {
				$prev = self::previous_meaningful( $tokens, $i - 1 );
				if ( is_array( $prev ) && T_FUNCTION === $prev[0] ) {
					continue;
				}
				$class = '';
				$kind  = 'function_call';
				if ( is_array( $prev ) && T_DOUBLE_COLON === $prev[0] ) {
					$class = self::previous_string( $tokens, $i - 2 );
					$kind  = 'static_call';
				} elseif ( is_array( $prev ) && T_OBJECT_OPERATOR === $prev[0] ) {
					$kind = 'method_call';
				}
				$calls[] = array( 'type' => $kind, 'class' => $class, 'name' => $text, 'scope' => $current_class, 'file' => $file, 'line' => $line );
			}
		}
		return array( 'definitions' => $definitions, 'calls' => $calls );
	}

	private static function next_string( $tokens, $start ) {
		$count = count( $tokens );
		for ( $i = $start; $i < $count; $i++ ) {
			$t = $tokens[ $i ];
			if ( is_array( $t ) && T_STRING === $t[0] ) {
				return $t[1];
			}
			if ( '(' === $t || '{' === $t || ';' === $t ) {
				break;
			}
		}
		return '';
	}

	private static function next_non_whitespace_is( $tokens, $start, $needle ) {
		$count = count( $tokens );
		for ( $i = $start; $i < $count; $i++ ) {
			$t = $tokens[ $i ];
			if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				continue;
			}
			return $needle === $t;
		}
		return false;
	}

	private static function previous_meaningful( $tokens, $start ) {
		for ( $i = $start; $i >= 0; $i-- ) {
			$t = $tokens[ $i ];
			if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				continue;
			}
			return $t;
		}
		return null;
	}

	private static function previous_string( $tokens, $start ) {
		$name_ids = array( T_STRING );
		if ( defined( 'T_NAME_QUALIFIED' ) ) {
			$name_ids[] = constant( 'T_NAME_QUALIFIED' );
		}
		if ( defined( 'T_NAME_FULLY_QUALIFIED' ) ) {
			$name_ids[] = constant( 'T_NAME_FULLY_QUALIFIED' );
		}
		for ( $i = $start; $i >= 0; $i-- ) {
			$t = $tokens[ $i ];
			if ( is_array( $t ) && in_array( $t[0], $name_ids, true ) ) {
				return ltrim( $t[1], '\\' );
			}
			if ( ';' === $t || '{' === $t || '}' === $t ) {
				break;
			}
		}
		return '';
	}

	private static function wanted_symbols( $job ) {
		$text = wp_json_encode(
			array(
				'incident'  => isset( $job['incident'] ) ? $job['incident'] : array(),
				'analysis'  => isset( $job['analysis'] ) ? $job['analysis'] : array(),
				'challenge' => isset( $job['challenge'] ) ? $job['challenge'] : array(),
			),
			JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
		);
		$classes = array();
		$methods = array();
		if ( preg_match_all( '/\b([A-Z][A-Za-z0-9_]{4,})::([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $text, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $row ) {
				$classes[] = $row[1];
				$methods[] = $row[2];
			}
		}
		if ( preg_match_all( '/\b([A-Z][A-Za-z0-9_]{8,})\b/', $text, $m ) ) {
			$classes = array_merge( $classes, $m[1] );
		}
		if ( preg_match_all( '/\b([a-z_][A-Za-z0-9_]{2,})\s*\(\)/', $text, $m ) ) {
			$methods = array_merge( $methods, $m[1] );
		}
		$classes = array_values( array_unique( array_slice( array_filter( $classes ), 0, 20 ) ) );
		$methods = array_values( array_unique( array_slice( array_filter( $methods ), 0, 20 ) ) );
		return array( 'classes' => $classes, 'methods' => $methods );
	}

	private static function filter_definitions( $definitions, $wanted ) {
		$out = array();
		foreach ( $definitions as $d ) {
			$class_match = ! empty( $d['class'] ) && in_array( $d['class'], $wanted['classes'], true );
			$name_match  = in_array( $d['name'], $wanted['methods'], true ) || in_array( $d['name'], $wanted['classes'], true );
			if ( $class_match || $name_match ) {
				$out[] = $d;
			}
		}
		return $out;
	}

	private static function filter_calls( $calls, $wanted ) {
		$out = array();
		foreach ( $calls as $c ) {
			if ( in_array( $c['name'], $wanted['methods'], true ) || ( ! empty( $c['class'] ) && in_array( $c['class'], $wanted['classes'], true ) ) ) {
				$out[] = $c;
			}
		}
		return $out;
	}

	private static function duplicates( $definitions, $wanted ) {
		$groups = array();
		foreach ( $definitions as $d ) {
			$key = 'class' === $d['type'] ? 'class:' . strtolower( $d['name'] ) : strtolower( $d['class'] . '::' . $d['name'] );
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = array();
			}
			$groups[ $key ][] = $d;
		}
		$out = array();
		foreach ( $groups as $key => $items ) {
			if ( count( $items ) > 1 ) {
				$name = isset( $items[0]['name'] ) ? $items[0]['name'] : '';
				$class = isset( $items[0]['class'] ) ? $items[0]['class'] : '';
				if ( in_array( $name, $wanted['methods'], true ) || in_array( $name, $wanted['classes'], true ) || in_array( $class, $wanted['classes'], true ) ) {
					$out[] = array( 'symbol' => $key, 'locations' => $items );
				}
			}
		}
		return $out;
	}

	private static function alternatives( $definitions, $wanted ) {
		$out = array();
		foreach ( $definitions as $d ) {
			if ( 'method' !== $d['type'] || ! in_array( $d['class'], $wanted['classes'], true ) || 'private' === $d['visibility'] ) {
				continue;
			}
			foreach ( $wanted['methods'] as $method ) {
				$prefix = preg_replace( '/_.*/', '', $method );
				if ( false !== stripos( $d['name'], $prefix ) || false !== stripos( $d['name'], 'render' ) ) {
					$out[] = $d;
					break;
				}
			}
		}
		return $out;
	}

	private static function relevant_hashes( $hashes, $definitions, $calls, $target ) {
		$files = array( $target );
		foreach ( array_merge( $definitions, $calls ) as $item ) {
			if ( ! empty( $item['file'] ) ) {
				$files[] = $item['file'];
			}
		}
		$files = array_values( array_unique( $files ) );
		$out = array();
		foreach ( array_slice( $files, 0, 30 ) as $file ) {
			if ( isset( $hashes[ $file ] ) ) {
				$out[ $file ] = $hashes[ $file ];
			}
		}
		return $out;
	}


	/**
	 * Inspecciona únicamente símbolos que ya están cargados en el proceso actual.
	 * No dispara autoload ni ejecuta archivos adicionales.
	 *
	 * @param array $wanted      Símbolos buscados.
	 * @param array $definitions Definiciones del disco.
	 * @param array $file_hashes Hashes del disco.
	 * @return array
	 */
	private static function runtime_evidence( $wanted, $definitions, $file_hashes ) {
		$out = array(
			'available'   => class_exists( 'ReflectionClass', false ),
			'classes'     => array(),
			'methods'     => array(),
			'comparisons' => array(),
			'opcache'     => self::opcache_evidence(),
			'summary'     => array(),
		);
		if ( empty( $out['available'] ) ) {
			$out['summary'][] = __( 'PHP reflection is not available in this environment.', 'ai-bug-hunter' );
			return $out;
		}

		$disk = array();
		foreach ( $definitions as $definition ) {
			if ( ! is_array( $definition ) || empty( $definition['class'] ) || empty( $definition['name'] ) ) {
				continue;
			}
			$disk[ strtolower( $definition['class'] . '::' . $definition['name'] ) ] = $definition;
		}

		foreach ( array_slice( isset( $wanted['classes'] ) ? (array) $wanted['classes'] : array(), 0, 12 ) as $class ) {
			$class = ltrim( (string) $class, '\\' );
			if ( '' === $class ) {
				continue;
			}
			if ( ! class_exists( $class, false ) && ! interface_exists( $class, false ) && ! trait_exists( $class, false ) ) {
				$out['classes'][] = array( 'class' => $class, 'loaded' => false );
				continue;
			}
			try {
				$reflection = new ReflectionClass( $class );
				$file       = $reflection->getFileName();
				$relative   = is_string( $file ) ? self::relative( $file ) : '';
				$hash       = is_string( $file ) && is_readable( $file ) ? hash_file( 'sha256', $file ) : '';
				$out['classes'][] = array(
					'class'      => $class,
					'loaded'     => true,
					'file'       => $relative,
					'start_line' => (int) $reflection->getStartLine(),
					'end_line'   => (int) $reflection->getEndLine(),
					'sha256'     => is_string( $hash ) ? $hash : '',
					'filemtime'  => is_string( $file ) && file_exists( $file ) ? (int) @filemtime( $file ) : 0,
				);

				foreach ( array_slice( isset( $wanted['methods'] ) ? (array) $wanted['methods'] : array(), 0, 20 ) as $method ) {
					$key = strtolower( $class . '::' . $method );
					if ( ! $reflection->hasMethod( $method ) ) {
						if ( isset( $disk[ $key ] ) ) {
							$definition = $disk[ $key ];
							$out['methods'][] = array(
								'class'  => $class,
								'name'   => $method,
								'exists' => false,
							);
							$out['comparisons'][] = array(
								'symbol'             => $class . '::' . $method,
								'disk_visibility'    => isset( $definition['visibility'] ) ? $definition['visibility'] : '',
								'runtime_visibility' => 'missing',
								'disk_file'          => isset( $definition['file'] ) ? $definition['file'] : '',
								'runtime_file'       => $relative,
								'visibility_matches' => false,
								'file_matches'       => empty( $relative ) || empty( $definition['file'] ) || $relative === $definition['file'],
								'contradiction'      => true,
							);
						}
						continue;
					}
					$rm = $reflection->getMethod( $method );
					$visibility = $rm->isPrivate() ? 'private' : ( $rm->isProtected() ? 'protected' : 'public' );
					$runtime = array(
						'class'      => $class,
						'name'       => $method,
						'visibility' => $visibility,
						'exists'     => true,
						'static'     => $rm->isStatic(),
						'parameters' => $rm->getNumberOfParameters(),
						'required_parameters' => $rm->getNumberOfRequiredParameters(),
						'file'       => is_string( $rm->getFileName() ) ? self::relative( $rm->getFileName() ) : '',
						'start_line' => (int) $rm->getStartLine(),
						'end_line'   => (int) $rm->getEndLine(),
					);
					$out['methods'][] = $runtime;
					if ( isset( $disk[ $key ] ) ) {
						$definition = $disk[ $key ];
						$same_visibility = isset( $definition['visibility'] ) && $visibility === $definition['visibility'];
						$same_file = empty( $runtime['file'] ) || empty( $definition['file'] ) || $runtime['file'] === $definition['file'];
						$out['comparisons'][] = array(
							'symbol'              => $class . '::' . $method,
							'disk_visibility'     => isset( $definition['visibility'] ) ? $definition['visibility'] : '',
							'runtime_visibility'  => $visibility,
							'disk_file'           => isset( $definition['file'] ) ? $definition['file'] : '',
							'runtime_file'        => $runtime['file'],
							'visibility_matches'  => $same_visibility,
							'file_matches'        => $same_file,
							'contradiction'       => ! $same_visibility || ! $same_file,
						);
					}
				}
			} catch ( ReflectionException $e ) {
				$out['classes'][] = array( 'class' => $class, 'loaded' => true, 'error' => sanitize_text_field( $e->getMessage() ) );
			} catch ( Throwable $e ) {
				$out['classes'][] = array( 'class' => $class, 'loaded' => true, 'error' => sanitize_text_field( $e->getMessage() ) );
			}
		}

		$loaded = 0;
		foreach ( $out['classes'] as $class_row ) {
			if ( ! empty( $class_row['loaded'] ) ) {
				$loaded++;
			}
		}
		if ( $loaded > 0 ) {
			$out['summary'][] = sprintf(
				/* translators: 1: loaded classes, 2: runtime methods. */
				__( 'The runtime probe found %1$d class(es) already loaded and verified %2$d method(s) via Reflection.', 'ai-bug-hunter' ),
				$loaded,
				count( $out['methods'] )
			);
		} else {
			$out['summary'][] = __( 'The classes investigated were not loaded in this request; runtime evidence remains pending.', 'ai-bug-hunter' );
		}
		$contradictions = array_filter( $out['comparisons'], static function ( $row ) {
			return ! empty( $row['contradiction'] );
		} );
		if ( $contradictions ) {
			$out['summary'][] = __( 'The definition loaded by PHP contradicts the file analyzed on disk. This points to mixed versions, a stale OPcache or a different load path.', 'ai-bug-hunter' );
		} elseif ( $out['comparisons'] ) {
			$out['summary'][] = __( 'The visibility and the path observed at runtime match the current code on disk.', 'ai-bug-hunter' );
		}
		return $out;
	}

	/**
	 * Obtiene únicamente señales no secretas de OPcache.
	 *
	 * @return array
	 */
	private static function opcache_evidence() {
		$out = array(
			'available'           => function_exists( 'opcache_get_configuration' ),
			'enabled'             => false,
			'validate_timestamps' => null,
			'revalidate_freq'     => null,
			'restrict_api_configured' => false,
		);
		if ( ! $out['available'] ) {
			return $out;
		}
		try {
			$config = opcache_get_configuration();
			$directives = is_array( $config ) && isset( $config['directives'] ) && is_array( $config['directives'] ) ? $config['directives'] : array();
			$out['enabled']             = ! empty( $directives['opcache.enable'] );
			$out['validate_timestamps'] = isset( $directives['opcache.validate_timestamps'] ) ? (bool) $directives['opcache.validate_timestamps'] : null;
			$out['revalidate_freq']     = isset( $directives['opcache.revalidate_freq'] ) ? (int) $directives['opcache.revalidate_freq'] : null;
			$out['restrict_api_configured'] = ! empty( $directives['opcache.restrict_api'] );
		} catch ( Throwable $e ) {
			$out['error'] = sanitize_text_field( $e->getMessage() );
		}
		return $out;
	}

	private static function project_version( $root ) {
		$files = glob( trailingslashit( $root ) . '*.php' );
		foreach ( (array) $files as $file ) {
			$head = @file_get_contents( $file, false, null, 0, 8192 );
			if ( false !== $head && preg_match( '/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m ) ) {
				return sanitize_text_field( trim( $m[1] ) );
			}
		}
		return '';
	}

	private static function relative( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$base = trailingslashit( wp_normalize_path( ABSPATH ) );
		return 0 === strpos( $abs, $base ) ? ltrim( substr( $abs, strlen( $base ) ), '/' ) : basename( $abs );
	}
}
