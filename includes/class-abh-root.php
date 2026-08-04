<?php
/**
 * Modo root: el superpoder que se ARMA, no se quita.
 *
 * Resuelve la tensión entera del producto. AI Bug Hunter puede tocar todo el
 * sitio, y eso es la función, no un descuido. Pero hay reparaciones que un
 * clic distraído no debería poder disparar: salir de wp-content, tocar el
 * núcleo, mover o borrar archivos, cambiar permisos, o aplicar un parche que
 * el diferencial de capacidades marcó en rojo.
 *
 * La respuesta NO es negarlas. Es pedir que alguien las firme.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Decide qué reparaciones exigen firma y guarda el recibo de
 * quién armó el modo root, cuándo, con qué frase y para qué alcance exacto.
 *
 * POR QUE EXISTE:  Es lo que permite conservar el acceso total sin que sea un
 * accidente. Sin esta pieza sólo quedarían dos salidas malas: recortar el
 * alcance del producto, o dejar que un doble clic reescriba el núcleo.
 *
 * SI LO RECORTAS:  Si haces que TODO exija la frase, la gente la teclea sin
 * leer y deja de proteger. Si haces que NADA la exija, el aviso desaparece.
 * Y si conviertes esto en una negativa —«no puedo hacer eso»— rompes la
 * doctrina: aquí nada se niega, se pospone hasta que alguien lo firme.
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
 * Class ABH_Root
 */
class ABH_Root {

	/**
	 * Dónde se guarda el armado en curso.
	 */
	const OPTION = 'abh_root_armado';

	/**
	 * Cuánto dura el armado sin renovarse.
	 *
	 * Quince minutos: lo justo para encadenar un plan y sus reintentos sin
	 * volver a teclear, y lo bastante corto para que no sobreviva a un café.
	 */
	const VENTANA = 900;

	/**
	 * La frase que hay que escribir.
	 *
	 * Se puede pegar. El punto no es la fricción física —eso sólo molesta— sino
	 * que nadie pueda decir después que hizo clic sin leer.
	 */
	const FRASE = 'I accept the change and the risks';

	/**
	 * Normaliza una frase escrita por una persona.
	 *
	 * Sin distinguir mayúsculas, ni acentos, ni espacios de más. Fallar por una
	 * tilde convertiría una decisión consciente en un acertijo.
	 *
	 * @param string $texto Lo que se tecleó.
	 * @return string
	 */
	public static function normaliza( $texto ) {
		$t = function_exists( 'mb_strtolower' ) ? mb_strtolower( trim( (string) $texto ), 'UTF-8' ) : strtolower( trim( (string) $texto ) );
		$t = strtr(
			$t,
			array(
				'á' => 'a',
				'é' => 'e',
				'í' => 'i',
				'ó' => 'o',
				'ú' => 'u',
				'ü' => 'u',
				'ñ' => 'n',
			)
		);
		return preg_replace( '/\s+/', ' ', $t );
	}

	/**
	 * ¿La frase es la correcta?
	 *
	 * @param string $texto Lo que se tecleó.
	 * @return bool
	 */
	public static function frase_ok( $texto ) {
		return hash_equals( self::normaliza( self::FRASE ), self::normaliza( $texto ) );
	}

	/**
	 * Qué motivos, de haberlos, obligan a armar el modo root para este plan.
	 *
	 * Devuelve una lista de motivos legibles. Vacía significa que la reparación
	 * es de las tranquilas y no hay que teclear nada: si todo lo pidiera, la
	 * frase dejaría de significar algo.
	 *
	 * @param array $payload Plan de operaciones (versión 3) o propuesta.
	 * @return array Lista de { clave, texto }.
	 */
	public static function motivos( $payload ) {
		$motivos = array();
		$ops     = self::operaciones( $payload );

		if ( count( $ops ) > 1 ) {
			$motivos[] = array(
				'clave' => 'multiarchivo',
				'texto' => sprintf(
					/* translators: %d: número de operaciones. */
					_n( 'It affects %d file in a single operation.', 'It affects %d files in a single operation.', count( $ops ), 'ai-bug-hunter' ),
					count( $ops )
				),
			);
		}

		foreach ( $ops as $op ) {
			$rel  = isset( $op['rel_path'] ) ? (string) $op['rel_path'] : '';
			$tipo = isset( $op['op'] ) ? (string) $op['op'] : '';

			// Una ruta vacía NO es inocua: significa que no sabemos qué se toca.
			// Tratarla como tranquila sería firmar en blanco por omisión.
			if ( '' === $rel ) {
				$motivos[] = array(
					'clave' => 'sin_ruta',
					'texto' => __( 'There is an operation with no path: there is no way to know what it touches.', 'ai-bug-hunter' ),
				);
				continue;
			}
			if ( 0 !== strpos( $rel, 'wp-content/' ) ) {
				$motivos[] = array(
					'clave' => 'fuera',
					'texto' => sprintf(
						/* translators: %s: ruta. */
						__( 'Leaves wp-content: it touches %s.', 'ai-bug-hunter' ),
						$rel
					),
				);
			}
			if ( 0 === strpos( $rel, 'wp-content/mu-plugins/' ) ) {
				$motivos[] = array(
					'clave' => 'mu',
					'texto' => sprintf(
						/* translators: %s: ruta. */
						__( 'Installs or changes a mu-plugin (%s), which loads before everything else.', 'ai-bug-hunter' ),
						$rel
					),
				);
			}
			if ( in_array( $tipo, array( 'mover', 'quitar', 'permisos' ), true ) ) {
				$motivos[] = array(
					'clave' => $tipo,
					'texto' => sprintf(
						/* translators: 1: operación, 2: ruta. */
						__( 'Not just an edit: %1$s on %2$s.', 'ai-bug-hunter' ),
						$tipo,
						$rel
					),
				);
			}
		}

		// Señales del diferencial de capacidades: un parche que introduce cosas
		// que antes no estaban se firma, aunque toque un solo archivo.
		if ( ! empty( $payload['senales'] ) && is_array( $payload['senales'] ) ) {
			foreach ( $payload['senales'] as $s ) {
				$motivos[] = array(
					'clave' => 'senal',
					'texto' => is_scalar( $s ) ? (string) $s : __( 'The patch introduces a capability the file did not have.', 'ai-bug-hunter' ),
				);
			}
		}

		return self::unicos( $motivos );
	}

	/**
	 * Las operaciones de un plan, venga en la forma que venga.
	 *
	 * El producto tiene TRES caminos de escritura y los tres pueden tocar cosas
	 * graves: el plan de operaciones (versión 3), el multi-archivo (versión 2,
	 * que trae `files[]`) y el de archivo único. Si esta función sólo entendiera
	 * uno, la firma se pediría en uno y los otros dos escribirían el núcleo o un
	 * mu-plugin sin que nadie firmara nada — que es exactamente lo que pasaba.
	 *
	 * Las rutas se normalizan aquí. Comprobar «empieza por wp-content/» sobre
	 * una ruta sin normalizar deja pasar `wp-content/../wp-admin/x.php`.
	 *
	 * @param array $payload Propuesta en cualquiera de sus formas.
	 * @return array Lista de { op, rel_path, destino, modo }.
	 */
	public static function operaciones( $payload ) {
		$out = array();

		if ( isset( $payload['ops'] ) && is_array( $payload['ops'] ) ) {
			foreach ( $payload['ops'] as $op ) {
				$out[] = array(
					'op'       => isset( $op['op'] ) ? (string) $op['op'] : 'escribir',
					'rel_path' => self::normaliza_ruta( isset( $op['rel_path'] ) ? $op['rel_path'] : '' ),
					'destino'  => self::normaliza_ruta( isset( $op['destino'] ) ? $op['destino'] : '' ),
					'modo'     => isset( $op['modo'] ) ? (string) $op['modo'] : '',
				);
			}
			return $out;
		}

		// Versión 2: el motor multi-archivo. Cada entrada de files[] es una
		// escritura sobre un archivo que ya existe.
		if ( isset( $payload['files'] ) && is_array( $payload['files'] ) ) {
			foreach ( $payload['files'] as $f ) {
				$out[] = array(
					'op'       => 'escribir',
					'rel_path' => self::normaliza_ruta( isset( $f['rel_path'] ) ? $f['rel_path'] : '' ),
					'destino'  => '',
					'modo'     => '',
				);
			}
			return $out;
		}

		// Archivo único.
		if ( ! empty( $payload['rel_path'] ) ) {
			$out[] = array(
				'op'       => 'escribir',
				'rel_path' => self::normaliza_ruta( $payload['rel_path'] ),
				'destino'  => '',
				'modo'     => '',
			);
		}
		return $out;
	}

	/**
	 * Normaliza una ruta relativa resolviendo `.` y `..`.
	 *
	 * @param string $rel Ruta.
	 * @return string
	 */
	private static function normaliza_ruta( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );
		if ( '' === $rel ) {
			return '';
		}
		$partes = array();
		foreach ( explode( '/', $rel ) as $seg ) {
			if ( '' === $seg || '.' === $seg ) {
				continue;
			}
			if ( '..' === $seg ) {
				array_pop( $partes );
				continue;
			}
			$partes[] = $seg;
		}
		return implode( '/', $partes );
	}

	/**
	 * Quita motivos repetidos conservando el orden.
	 *
	 * @param array $motivos Motivos.
	 * @return array
	 */
	private static function unicos( $motivos ) {
		$vistos = array();
		$out    = array();
		foreach ( $motivos as $m ) {
			$k = $m['clave'] . '|' . $m['texto'];
			if ( isset( $vistos[ $k ] ) ) {
				continue;
			}
			$vistos[ $k ] = true;
			$out[]        = $m;
		}
		return $out;
	}

	/**
	 * Huella del alcance exacto que se acepta.
	 *
	 * Se firma un plan concreto, no «lo que venga». Si el plan cambia entre la
	 * firma y la aplicación, el armado deja de valer: eso es justo lo que
	 * convierte una firma en un permiso y no en un cheque en blanco.
	 *
	 * @param array $payload Plan.
	 * @return string
	 */
	public static function huella( $payload ) {
		$plano = array();

		// El ORDEN entra en la huella. Ordenar la lista antes de hashear hacía
		// que «escribe a.php y luego muévelo» y «muévelo y luego escríbelo»
		// —que hacen cosas opuestas— compartieran firma: firmar uno armaba el
		// otro. En una transacción todo-o-nada el orden es el significado.
		if ( isset( $payload['ops'] ) && is_array( $payload['ops'] ) ) {
			foreach ( $payload['ops'] as $op ) {
				$plano[] = 'op|' . ( isset( $op['op'] ) ? $op['op'] : '' ) . '|'
					. ( isset( $op['rel_path'] ) ? $op['rel_path'] : '' ) . '|'
					. ( isset( $op['destino'] ) ? $op['destino'] : '' ) . '|'
					. ( isset( $op['modo'] ) ? $op['modo'] : '' ) . '|'
					. ( isset( $op['contenido'] ) ? hash( 'sha256', (string) $op['contenido'] ) : '' );
			}
		}
		if ( isset( $payload['files'] ) && is_array( $payload['files'] ) ) {
			foreach ( $payload['files'] as $f ) {
				$plano[] = 'file|' . ( isset( $f['rel_path'] ) ? $f['rel_path'] : '' ) . '|'
					. ( isset( $f['sha_before'] ) ? $f['sha_before'] : '' ) . '|'
					. ( isset( $f['patched'] ) ? hash( 'sha256', (string) $f['patched'] ) : '' );
			}
		}
		if ( ! $plano && ! empty( $payload['rel_path'] ) ) {
			$plano[] = 'uno|' . (string) $payload['rel_path'] . '|'
				. ( isset( $payload['sha_before'] ) ? $payload['sha_before'] : '' ) . '|'
				. ( isset( $payload['patched'] ) ? hash( 'sha256', (string) $payload['patched'] ) : '' );
		}

		// Las señales del diferencial forman parte de lo que se firmó: si
		// aparecen otras después, la firma ya no cubre lo que hay delante.
		if ( ! empty( $payload['senales'] ) && is_array( $payload['senales'] ) ) {
			$s = array_map( 'strval', $payload['senales'] );
			sort( $s );
			$plano[] = 'senales|' . implode( ',', $s );
		}

		// Un plan sin nada que hacer NO puede tener una huella válida: el hash
		// de la cadena vacía es una constante, y firmarlo armaría cualquier
		// otro payload igual de vacío.
		if ( ! $plano ) {
			return '';
		}
		return hash( 'sha256', implode( "\n", $plano ) );
	}

	/**
	 * La compuerta. Único punto por el que se decide si hace falta firma.
	 *
	 * Existe para que NO haya tres compuertas distintas. El producto tiene tres
	 * caminos de escritura y al principio sólo uno la consultaba: los otros dos
	 * —incluido el multi-archivo, que es el que de verdad toca N archivos—
	 * escribían el núcleo y los mu-plugins sin que nadie firmara nada.
	 *
	 * Devuelve null cuando se puede seguir, y el array de respuesta cuando hay
	 * que esperar una firma. Nunca cancela: conserva el token, el diagnóstico y
	 * el plan enteros.
	 *
	 * @param array  $payload Propuesta.
	 * @param string $token   Token de la propuesta, para poder firmarla.
	 * @return array|null
	 */
	public static function compuerta( $payload, $token ) {
		$motivos = self::motivos( $payload );
		if ( ! $motivos || self::armado_para( $payload ) ) {
			return null;
		}
		return array(
			'ok'            => false,
			'requiere_root' => true,
			'motivos'       => wp_list_pluck( $motivos, 'texto' ),
			'frase'         => self::FRASE,
			'token'         => (string) $token,
			'message'       => __( 'This repair needs root-level access. I have not cancelled it: it is waiting for you to sign it.', 'ai-bug-hunter' ),
		);
	}

	/**
	 * ¿Se usó la firma para ESTE plan? Sirve para saber si toca recibo.
	 *
	 * @param array $payload Plan aplicado.
	 * @return bool
	 */
	public static function se_uso_para( $payload ) {
		return (bool) self::motivos( $payload ) && false !== self::armado();
	}

	/**
	 * Arma el modo root para un plan concreto.
	 *
	 * @param array  $payload Plan que se va a aplicar.
	 * @param string $frase   Lo que tecleó la persona.
	 * @return array { ok } | { ok:false, message }
	 */
	public static function armar( $payload, $frase ) {
		if ( ! self::frase_ok( $frase ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: frase exacta. */
					__( 'The phrase does not match. Type exactly: %s', 'ai-bug-hunter' ),
					self::FRASE
				),
			);
		}
		$huella = self::huella( $payload );
		if ( '' === $huella ) {
			return array(
				'ok'      => false,
				'message' => __( 'That plan has nothing to sign. Analyze the error again.', 'ai-bug-hunter' ),
			);
		}
		$motivos = self::motivos( $payload );
		update_option(
			self::OPTION,
			array(
				'huella'  => $huella,
				'txn'     => isset( $payload['txn_id'] ) ? (string) $payload['txn_id'] : '',
				'at'      => time(),
				'user'    => get_current_user_id(),
				'motivos' => wp_list_pluck( $motivos, 'texto' ),
			),
			false
		);
		return array( 'ok' => true );
	}

	/**
	 * ¿Está armado el modo root para ESTE plan?
	 *
	 * @param array $payload Plan.
	 * @return bool
	 */
	public static function armado_para( $payload ) {
		$a = get_option( self::OPTION, array() );
		if ( ! is_array( $a ) || empty( $a['huella'] ) ) {
			return false;
		}
		if ( ( time() - ( isset( $a['at'] ) ? (int) $a['at'] : 0 ) ) > self::VENTANA ) {
			return false;
		}
		// El armado es de quien lo firmó. Otra sesión administrativa vuelve a
		// firmar: la responsabilidad no se hereda.
		if ( ( isset( $a['user'] ) ? (int) $a['user'] : 0 ) !== get_current_user_id() ) {
			return false;
		}
		$mia = self::huella( $payload );
		// Una huella vacia no autoriza nada: es lo que devuelve un plan sin
		// operaciones, y firmarla armaria cualquier otro plan igual de vacio.
		if ( '' === $mia ) {
			return false;
		}
		return hash_equals( (string) $a['huella'], $mia );
	}

	/**
	 * El armado en curso, para pintarlo.
	 *
	 * @return array|false
	 */
	public static function armado() {
		$a = get_option( self::OPTION, array() );
		if ( ! is_array( $a ) || empty( $a['huella'] ) ) {
			return false;
		}
		if ( ( time() - ( isset( $a['at'] ) ? (int) $a['at'] : 0 ) ) > self::VENTANA ) {
			return false;
		}
		// El armado es de quien lo firmo. Ensenarle a otro administrador
		// «MODO ROOT ARMADO» le diria que tiene un poder que no tiene.
		if ( ( isset( $a['user'] ) ? (int) $a['user'] : 0 ) !== get_current_user_id() ) {
			return false;
		}
		return $a;
	}

	/**
	 * Desarma. Se llama al terminar el plan y al cerrar la consola.
	 *
	 * @return void
	 */
	public static function desarmar() {
		delete_option( self::OPTION );
	}

	/**
	 * Deja el recibo en el Historial.
	 *
	 * Queda quién armó, cuándo, para qué plan y con qué motivos. Un permiso sin
	 * recibo es un permiso que nadie puede auditar.
	 *
	 * @param array  $payload Plan aplicado.
	 * @param string $txn_id  Transacción.
	 * @return void
	 */
	public static function recibo( $payload, $txn_id ) {
		$a = get_option( self::OPTION, array() );
		if ( ! is_array( $a ) || empty( $a['huella'] ) || ! class_exists( 'ABH_Backup' ) ) {
			return;
		}
		$quien = get_userdata( (int) $a['user'] );
		ABH_Backup::record(
			array(
				'op_id'     => 'ROOT-' . (string) $txn_id,
				'txn_id'    => (string) $txn_id,
				'action'    => 'root',
				'status'    => 'applied',
				'rel_path'  => '',
				'diagnosis' => sprintf(
					/* translators: 1: usuario, 2: frase, 3: motivos. */
					__( 'Root mode armed by %1$s writing «%2$s». Reasons: %3$s', 'ai-bug-hunter' ),
					$quien ? $quien->user_login : ( '#' . (int) $a['user'] ),
					self::FRASE,
					implode( ' · ', (array) ( isset( $a['motivos'] ) ? $a['motivos'] : array() ) )
				),
			)
		);
	}
}
