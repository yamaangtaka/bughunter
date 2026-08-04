<?php
/**
 * Estado del sistema: ¿hay sitio para respaldar antes de tocar nada?
 *
 * Todo lo que promete este plugin —«es reversible», «se revierte en un clic»—
 * se apoya en una copia guardada en disco. Si no hay espacio, la copia no se
 * hace, y sin copia no hay reversión: la promesa se cae en silencio justo
 * cuando más falta hace.
 *
 * Peor todavía: una transacción podría empezar bien y quedarse sin espacio a la
 * mitad. Por eso el espacio se comprueba ANTES de la primera operación, no
 * cuando ya se tocó algo.
 *
 * No se toca la base de datos, así que aquí no hay nada que medir de ella.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Borra carpetas de copias de seguridad.
 *
 * POR QUE EXISTE:  Sin poda, las copias llenan el disco y tumban el sitio que venían a proteger.
 *
 * SI LO RECORTAS:  Nunca poda una transacción en curso ni una reversión que quedó a medias: sus copias son la única forma de terminar de deshacerla.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Health cleanup deletes only normalized plugin-owned cache directories after boundary checks.

/**
 * Class ABH_Health
 */
class ABH_Health {

	/**
	 * Margen fijo que se reserva siempre, además del tamaño de la copia.
	 *
	 * Un disco al borde falla de formas raras: WordPress escribe transitorios,
	 * el propio PHP escribe temporales, y el registro sigue creciendo. Diez
	 * megas es barato y evita esa clase de fallo.
	 */
	const MARGEN = 10485760;

	/**
	 * Estados en los que una transacción todavía tiene marcha atrás pendiente.
	 *
	 * `aplicando` es una reparación que está escribiendo AHORA. `revertida_parcial`
	 * es una vuelta atrás que se quedó a medias. En los dos casos las copias son
	 * lo único que permite terminar de deshacerla, y borrarlas deja el sitio
	 * parcheado y sin marcha atrás, en silencio.
	 *
	 * Es una sola lista a propósito. Estaba escrita a mano dentro de prune_en()
	 * y la purga de ABH_Backup no la miraba: con dos listas, reforzar una deja
	 * la otra abierta sin que nada lo note. Quien necesite el mismo criterio
	 * pregunta aquí.
	 */
	const EN_VUELO = array( 'aplicando', 'revertida_parcial' );

	/**
	 * ¿Hay una transacción a medio aplicar o a medio revertir?
	 *
	 * @param string $txn_id Transacción concreta. Vacío pregunta por todas.
	 * @return bool
	 */
	public static function transaccion_en_vuelo( $txn_id = '' ) {
		if ( ! class_exists( 'ABH_Transaction' ) ) {
			return false;
		}
		$txn    = (string) $txn_id;
		$diario = get_option( ABH_Transaction::DIARIO, array() );
		$diario = is_array( $diario ) ? $diario : array();
		foreach ( $diario as $id => $asiento ) {
			if ( ! is_array( $asiento ) ) {
				continue;
			}
			if ( '' !== $txn && (string) $id !== $txn ) {
				continue;
			}
			$estado = isset( $asiento['estado'] ) ? (string) $asiento['estado'] : '';
			if ( in_array( $estado, self::EN_VUELO, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Espacio del disco donde vive el sitio.
	 *
	 * @return array libre, total, usado_pct
	 */
	public static function disk() {
		$base  = defined( 'ABSPATH' ) ? ABSPATH : '.';
		$libre = @disk_free_space( $base );
		$total = @disk_total_space( $base );

		$libre = is_numeric( $libre ) ? (float) $libre : 0.0;
		$total = is_numeric( $total ) ? (float) $total : 0.0;
		if ( $libre > $total ) {
			$libre = $total;
		}

		return array(
			'libre'     => $libre,
			'total'     => $total,
			'usado_pct' => $total > 0 ? round( ( ( $total - $libre ) / $total ) * 100, 1 ) : 0,
		);
	}

	/**
	 * Lo que ocupan las copias de las transacciones.
	 *
	 * @return array bytes, transacciones
	 */
	public static function ocupacion() {
		$bytes  = 0;
		$cuenta = 0;
		// Se cuentan LAS DOS ubicaciones. Enseñar sólo la nueva haría que el
		// espacio que ocupan las copias antiguas no apareciera en ningún sitio,
		// y el dueño no puede liberar lo que no ve.
		foreach ( self::dirs_undo() as $dir ) {
		if ( ! is_string( $dir ) || '' === $dir || ! is_dir( $dir ) ) {
			continue;
		}
		foreach ( (array) @scandir( $dir ) as $entrada ) {
			if ( '.' === $entrada || '..' === $entrada ) {
				continue;
			}
			$sub = $dir . '/' . $entrada;
			// Un enlace no ocupa lo que ocupa su destino, y el destino no es
			// nuestro: contarlo inflaría la cifra con megas que este plugin no
			// puede liberar. Se salta, igual que se salta al borrar.
			if ( ! is_dir( $sub ) || is_link( $sub ) ) {
				continue;
			}
			$cuenta++;
			foreach ( (array) @scandir( $sub ) as $archivo ) {
				if ( '.' === $archivo || '..' === $archivo ) {
					continue;
				}
				$tam    = @filesize( $sub . '/' . $archivo );
				$bytes += is_numeric( $tam ) ? (int) $tam : 0;
			}
		}
		}
		return array( 'bytes' => $bytes, 'transacciones' => $cuenta );
	}

	/**
	 * ¿Cabe una copia de este tamaño, con margen?
	 *
	 * @param int $bytes Tamaño de lo que hay que respaldar.
	 * @return array ok, message, necesario, libre
	 */
	public static function room_for( $bytes ) {
		$bytes     = max( 0, (float) $bytes );
		$necesario = $bytes + self::MARGEN;
		$d         = self::disk();

		if ( $d['total'] <= 0 ) {
			// Sin poder medir el disco no se inventa un veredicto: se deja
			// pasar, porque negarlo dejaría el plugin inútil en hospedajes que
			// desactivan estas funciones. Si luego el respaldo falla, falla
			// ruidosamente y la transacción se detiene igual.
			return array( 'ok' => true, 'message' => '', 'necesario' => $necesario, 'libre' => 0 );
		}

		if ( $d['libre'] >= $necesario ) {
			return array( 'ok' => true, 'message' => '', 'necesario' => $necesario, 'libre' => $d['libre'] );
		}

		return array(
			'ok'        => false,
			'necesario' => $necesario,
			'libre'     => $d['libre'],
			'message'   => sprintf(
				/* translators: 1: espacio necesario, 2: espacio libre. */
				__( 'There is not enough disk space to back up before touching anything: %1$s would be needed and %2$s is left. Nothing was modified. Free up space and try again.', 'ai-bug-hunter' ),
				size_format( $necesario, 1 ),
				size_format( $d['libre'], 1 )
			),
		);
	}

	/**
	 * Suma el tamaño de lo que un plan va a respaldar y escribir.
	 *
	 * @param array $ops Operaciones del plan.
	 * @return int Bytes.
	 */
	public static function peso_de( $ops ) {
		$total = 0;
		foreach ( (array) $ops as $op ) {
			if ( empty( $op['rel_path'] ) ) {
				continue;
			}
			// Sólo se respalda lo que ya existe: crear un archivo no copia nada.
			$abs = class_exists( 'ABH_Transaction' ) ? ABH_Transaction::absolute( $op['rel_path'] ) : false;
			if ( false !== $abs && file_exists( $abs ) ) {
				$tam    = @filesize( $abs );
				$total += is_numeric( $tam ) ? (int) $tam : 0;
			}
			// Y lo que se va a escribir también ocupa.
			if ( isset( $op['contenido'] ) ) {
				$total += strlen( (string) $op['contenido'] );
			}
		}
		return $total;
	}

	/**
	 * Limpia copias que ya no sirven para nada.
	 *
	 * Dos casos distintos, y la diferencia importa:
	 *
	 *  · Huérfanas — carpetas sin asiento en el diario. Nadie las puede revertir
	 *    ya, así que sólo ocupan sitio. Se van siempre.
	 *  · Con asiento — todavía revertibles. Sólo se van si son más viejas que
	 *    los días indicados, y entonces también se quita su asiento: dejar el
	 *    asiento sin las copias sería prometer una reversión imposible.
	 *
	 * Lo que NO se hace: dar por liberado lo que no se pudo borrar. Un unlink()
	 * que falla y se descarta es cómo una carpeta huérfana se queda para siempre
	 * mientras la pantalla dice que ya no está. Los fallos suben hasta aquí.
	 *
	 * @param int $dias Antigüedad a partir de la cual se retiran las vivas.
	 * @return array bytes, carpetas, errores, error
	 */
	public static function prune( $dias = 30 ) {
		$bytes_total    = 0;
		$carpetas_total = 0;
		$errores        = array();
		foreach ( self::dirs_undo() as $una ) {
			$r               = self::prune_en( $una, $dias );
			$bytes_total    += $r['bytes'];
			$carpetas_total += $r['carpetas'];
			$errores         = array_merge( $errores, $r['errores'] );
		}

		// Mismo permiso mal puesto, mismo mensaje veinte veces: se dice una vez
		// y se corta, que el aviso sirva para leerlo.
		$errores = array_values( array_unique( $errores ) );
		if ( count( $errores ) > 10 ) {
			$errores = array_slice( $errores, 0, 10 );
		}

		return array(
			'bytes'    => $bytes_total,
			'carpetas' => $carpetas_total,
			'errores'  => $errores,
			'error'    => empty( $errores ) ? '' : implode( ' ', $errores ),
		);
	}

	/**
	 * Poda una sola carpeta de copias.
	 *
	 * @param string $dir  Carpeta absoluta.
	 * @param int    $dias Antigüedad de corte.
	 * @return array bytes, carpetas, errores
	 */
	private static function prune_en( $dir, $dias ) {
		if ( ! is_string( $dir ) || '' === $dir || ! is_dir( $dir ) ) {
			return array( 'bytes' => 0, 'carpetas' => 0, 'errores' => array() );
		}

		// Antes de borrar nada hay que saber DÓNDE se va a borrar. La ruta se
		// resuelve una vez aquí y viaja con cada llamada: todo lo que no caiga
		// dentro de ella se queda donde está.
		$raiz = self::raiz_podable( $dir );
		if ( false === $raiz ) {
			return array(
				'bytes'    => 0,
				'carpetas' => 0,
				'errores'  => array(
					__( 'The backup folder could not be confirmed as a location this plugin owns, so nothing was deleted.', 'ai-bug-hunter' ),
				),
			);
		}

		$diario = get_option( ABH_Transaction::DIARIO, array() );
		$diario = is_array( $diario ) ? $diario : array();
		$dia    = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
		$corte  = time() - ( max( 0, (int) $dias ) * $dia );

		$bytes    = 0;
		$carpetas = 0;
		$tocado   = false;
		$errores  = array();

		foreach ( (array) @scandir( $raiz ) as $entrada ) {
			if ( '.' === $entrada || '..' === $entrada ) {
				continue;
			}
			$sub = $raiz . '/' . $entrada;
			if ( ! is_dir( $sub ) ) {
				continue;
			}

			$viva = isset( $diario[ $entrada ] );
			if ( $viva ) {
				// Una transacción en curso, o una reversión que quedó a medias,
				// NO se poda nunca por antigüedad. Su asiento existe justamente
				// para poder reintentar la vuelta atrás; barrerlo con la
				// limpieza rutinaria dejaría el sitio parcheado y sin marcha
				// atrás, en silencio, un mes después.
				$estado = isset( $diario[ $entrada ]['estado'] ) ? (string) $diario[ $entrada ]['estado'] : '';
				if ( in_array( $estado, self::EN_VUELO, true ) ) {
					continue;
				}
				$cuando = isset( $diario[ $entrada ]['at'] ) ? (int) $diario[ $entrada ]['at'] : 0;
				if ( $cuando > $corte ) {
					continue; // Reciente y revertible: no se toca.
				}
			}

			$r       = self::borrar_carpeta( $sub, $raiz );
			$bytes  += $r['bytes'];
			$errores = array_merge( $errores, $r['errores'] );

			// Si algo quedó en pie, la copia sigue ahí: ni se cuenta como
			// liberada ni se retira el asiento. Quitar el asiento de una copia
			// que no se borró es perder el rastro de lo que queda en disco.
			if ( empty( $r['ok'] ) ) {
				continue;
			}

			$carpetas++;
			if ( $viva ) {
				unset( $diario[ $entrada ] );
				$tocado = true;
			}
		}

		if ( $tocado && ! update_option( ABH_Transaction::DIARIO, $diario, false ) ) {
			// Las copias ya no están y el diario sigue prometiendo una reversión
			// que ya no puede hacerse. Es lo peor que puede pasar aquí y no se
			// calla.
			$errores[] = __( 'The old backups were deleted but the rollback journal could not be updated, so it may still list repairs that can no longer be reverted. Reload the page and run the cleanup again.', 'ai-bug-hunter' );
		}
		return array( 'bytes' => $bytes, 'carpetas' => $carpetas, 'errores' => $errores );
	}

	/**
	 * TODAS las carpetas donde puede haber copias.
	 *
	 * Son dos: la privada de hoy, fuera de la raíz web, y la que usaban las
	 * versiones anteriores dentro de `wp-content`. Mirar sólo una dejaría el
	 * código del cliente abandonado en su servidor para siempre después de
	 * actualizar, sin que nadie lo cuente ni lo barra.
	 *
	 * @return array Rutas absolutas existentes, sin repetir.
	 */
	private static function dirs_undo() {
		if ( ! class_exists( 'ABH_Transaction' ) ) {
			return array();
		}
		$candidatas = array();
		if ( method_exists( 'ABH_Transaction', 'dir_undo' ) ) {
			$candidatas[] = ABH_Transaction::dir_undo();
		}
		$candidatas[] = ABH_Transaction::absolute( ABH_Transaction::DIR_UNDO );

		$out = array();
		foreach ( $candidatas as $d ) {
			if ( is_string( $d ) && '' !== $d && ! in_array( $d, $out, true ) ) {
				$out[] = $d;
			}
		}
		return $out;
	}

	/**
	 * ¿Se puede podar aquí dentro? Devuelve la raíz ya resuelta.
	 *
	 * Un borrado recursivo sólo es aceptable dentro de una carpeta que es
	 * nuestra. Si lo que llega resuelve a la raíz del sitio, a `wp-content`, a
	 * la carpeta de subidas —o a cualquier carpeta que las contenga— no hay poda
	 * que valga: se devuelve false y no se toca ni un archivo.
	 *
	 * También se rechaza que la propia raíz sea un enlace: seguirlo pondría el
	 * borrado a trabajar en un destino que nadie eligió.
	 *
	 * @param string $dir Carpeta candidata.
	 * @return string|false Ruta resuelta y normalizada, o false.
	 */
	private static function raiz_podable( $dir ) {
		if ( ! is_string( $dir ) || '' === $dir || is_link( $dir ) ) {
			return false;
		}
		$real = @realpath( $dir );
		if ( false === $real ) {
			return false;
		}
		$real = rtrim( wp_normalize_path( $real ), '/' );
		if ( '' === $real || ! is_dir( $real ) ) {
			return false;
		}

		$prohibidas = array();
		if ( defined( 'ABSPATH' ) ) {
			$prohibidas[] = ABSPATH;
		}
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$prohibidas[] = WP_CONTENT_DIR;
		}
		$subidas = function_exists( 'wp_get_upload_dir' ) ? wp_get_upload_dir() : array();
		if ( is_array( $subidas ) && ! empty( $subidas['basedir'] ) ) {
			$prohibidas[] = $subidas['basedir'];
		}

		foreach ( $prohibidas as $una ) {
			$otra = @realpath( $una );
			$otra = false !== $otra ? $otra : $una;
			$otra = rtrim( wp_normalize_path( (string) $otra ), '/' );
			if ( '' === $otra ) {
				continue;
			}
			// Igual o por encima de una de ellas: la poda se llevaría el sitio.
			if ( 0 === strpos( $otra . '/', $real . '/' ) ) {
				return false;
			}
		}
		return $real;
	}

	/**
	 * ¿Esta ruta cae ESTRICTAMENTE dentro de la raíz de copias?
	 *
	 * @param string $ruta Ruta ya resuelta.
	 * @param string $raiz Raíz ya resuelta.
	 * @return bool
	 */
	private static function dentro_de( $ruta, $raiz ) {
		$ruta = rtrim( wp_normalize_path( (string) $ruta ), '/' );
		$raiz = rtrim( wp_normalize_path( (string) $raiz ), '/' );
		return '' !== $ruta && '' !== $raiz && 0 === strpos( $ruta, $raiz . '/' );
	}

	/**
	 * Nombre corto para un aviso, relativo a la raíz.
	 *
	 * La ruta absoluta del servidor no pinta nada en una pantalla de
	 * administración: no ayuda a arreglar el permiso y sí cuenta de más.
	 *
	 * @param string $ruta Ruta.
	 * @param string $raiz Raíz de copias.
	 * @return string
	 */
	private static function etiqueta( $ruta, $raiz ) {
		$ruta = rtrim( wp_normalize_path( (string) $ruta ), '/' );
		$raiz = rtrim( wp_normalize_path( (string) $raiz ), '/' );
		if ( '' !== $raiz && 0 === strpos( $ruta, $raiz . '/' ) ) {
			return substr( $ruta, strlen( $raiz ) + 1 );
		}
		return basename( $ruta );
	}

	/**
	 * Quita un enlace simbólico sin seguirlo jamás.
	 *
	 * En Linux unlink() basta, también cuando el enlace apunta a una carpeta. En
	 * Windows un enlace a carpeta sólo se quita con rmdir(), y rmdir() sobre un
	 * enlace borra el enlace, nunca el destino: por eso el segundo intento sigue
	 * siendo seguro.
	 *
	 * @param string $ruta Enlace.
	 * @return bool
	 */
	private static function quitar_enlace( $ruta ) {
		if ( @unlink( $ruta ) ) {
			return true;
		}
		return (bool) @rmdir( $ruta );
	}

	/**
	 * Borra una carpeta de copias y devuelve cuánto liberó.
	 *
	 * Dos reglas que no se negocian:
	 *
	 *  · Un enlace se borra COMO ENLACE. Bajar por él sería borrar en recursivo
	 *    su destino, que vive fuera de la carpeta de copias y no es nuestro. Un
	 *    enlace a carpeta plantado aquí dentro es todo lo que hace falta para
	 *    convertir una limpieza rutinaria en un borrado del sitio.
	 *  · La contención se comprueba en CADA nivel, no sólo al entrar. Comprobar
	 *    únicamente el primero deja la puerta abierta a que un nivel más abajo
	 *    resuelva a otro sitio.
	 *
	 * Y lo que devuelve importa tanto como lo que borra: un unlink() que falla y
	 * se descarta es la razón de que una carpeta huérfana siga en disco mientras
	 * la pantalla asegura que ya no está.
	 *
	 * @param string $dir  Carpeta.
	 * @param string $raiz Raíz de copias ya resuelta.
	 * @return array bytes, ok, errores
	 */
	private static function borrar_carpeta( $dir, $raiz ) {
		if ( is_link( $dir ) ) {
			if ( self::quitar_enlace( $dir ) ) {
				return array( 'bytes' => 0, 'ok' => true, 'errores' => array() );
			}
			return array(
				'bytes'   => 0,
				'ok'      => false,
				'errores' => array(
					sprintf(
						/* translators: %s: nombre de la entrada dentro de la carpeta de copias. */
						__( 'A symbolic link inside the backup folder could not be removed: %s. Nothing it points to was touched.', 'ai-bug-hunter' ),
						self::etiqueta( $dir, $raiz )
					),
				),
			);
		}

		$real = @realpath( $dir );
		if ( false === $real || ! is_dir( $real ) || ! self::dentro_de( $real, $raiz ) ) {
			return array(
				'bytes'   => 0,
				'ok'      => false,
				'errores' => array(
					sprintf(
						/* translators: %s: nombre de la entrada dentro de la carpeta de copias. */
						__( 'A backup entry was left alone because it does not resolve inside the plugin backup folder: %s. Nothing was deleted there.', 'ai-bug-hunter' ),
						self::etiqueta( $dir, $raiz )
					),
				),
			);
		}
		$real = rtrim( wp_normalize_path( $real ), '/' );

		$bytes   = 0;
		$errores = array();

		foreach ( (array) @scandir( $real ) as $archivo ) {
			if ( '.' === $archivo || '..' === $archivo ) {
				continue;
			}
			$ruta = $real . '/' . $archivo;

			// El enlace se mira ANTES que is_dir(): is_dir() dice que sí de un
			// enlace a carpeta, y ahí es donde se pierde el sitio.
			if ( is_link( $ruta ) ) {
				if ( ! self::quitar_enlace( $ruta ) ) {
					$errores[] = sprintf(
						/* translators: %s: nombre de la entrada dentro de la carpeta de copias. */
						__( 'A symbolic link inside the backup folder could not be removed: %s. Nothing it points to was touched.', 'ai-bug-hunter' ),
						self::etiqueta( $ruta, $raiz )
					);
				}
				continue;
			}

			if ( is_dir( $ruta ) ) {
				$hijo    = self::borrar_carpeta( $ruta, $raiz );
				$bytes  += $hijo['bytes'];
				$errores = array_merge( $errores, $hijo['errores'] );
				continue;
			}

			$tam = @filesize( $ruta );
			if ( @unlink( $ruta ) ) {
				$bytes += is_numeric( $tam ) ? (int) $tam : 0;
				continue;
			}
			$errores[] = sprintf(
				/* translators: %s: nombre del archivo dentro de la carpeta de copias. */
				__( 'A backup file could not be deleted: %s. Check the permissions of the plugin backup folder on the server; that space was not freed.', 'ai-bug-hunter' ),
				self::etiqueta( $ruta, $raiz )
			);
		}

		// Con algo dentro todavía en pie, rmdir() sólo puede fallar: no se
		// intenta para no añadir un segundo aviso por la misma causa.
		$ok = empty( $errores );
		if ( $ok && ! @rmdir( $real ) ) {
			$ok        = false;
			$errores[] = sprintf(
				/* translators: %s: nombre de la carpeta dentro de la carpeta de copias. */
				__( 'A backup folder could not be deleted: %s. Check the permissions of the plugin backup folder on the server.', 'ai-bug-hunter' ),
				self::etiqueta( $real, $raiz )
			);
		}

		return array( 'bytes' => $bytes, 'ok' => $ok, 'errores' => $errores );
	}
}
