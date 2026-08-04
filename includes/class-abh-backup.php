<?php
/**
 * Respaldo parcial cifrado, historial y reversión.
 *
 * Los respaldos nuevos se cifran con autenticación antes de tocar disco. La
 * carpeta privada vive DENTRO de la instalación —wp-content, o la base de
 * subidas si no se puede—, con 0700, .htaccess, web.config e index.php. Solo
 * ABH_BACKUP_DIR, que se escribe a mano en wp-config.php, la saca de ahí.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Restaura archivos sobre el sitio y borra copias de seguridad.
 *
 * POR QUE EXISTE:  La reversión es la red que hace aceptable todo lo demás. Restaurar es tan potente como escribir, y tiene que serlo.
 *
 * SI LO RECORTAS:  Si alguien impide que un administrador revierta lo que aplicó otro, mata el caso de agencia: dos personas turnándose sobre el mismo sitio es lo normal, no la excepción. Se pide confirmación, NO se prohíbe. Lo único que se rechaza sin salida es revertir lo que otra persona está aplicando en ese instante, y eso no es turnarse: es escribir los dos a la vez.
 *
 * Y NO BORRES:     La purga se niega mientras haya una transacción a medias. Sus copias son la única forma de terminar de deshacerla; sin ellas el sitio queda parcheado y sin marcha atrás, en silencio.
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

// phpcs:disable WordPress.WP.AlternativeFunctions -- Encrypted backups use streaming writes, explicit permissions, and atomic cleanup inside a locally verified private directory.

/**
 * Class ABH_Backup
 */
class ABH_Backup {

	const OPTION_JOURNAL = 'abh_journal';
	const MAX_ENTRIES    = 200;

	/**
	 * Candado del diario.
	 *
	 * El diario es UNA opción que se lee, se modifica y se vuelve a escribir.
	 * Dos operaciones a la vez —dos pestañas, dos administradores, un cron que
	 * cae encima de una reparación— leían la misma lista y la última en escribir
	 * borraba la fila de la otra. Esa fila es la que sabe dónde está el respaldo:
	 * sin ella el archivo .abhbak queda huérfano en disco y el cambio, sin marcha
	 * atrás. El candado vive poco y caduca solo, así que un proceso que muera a
	 * medias no deja el historial bloqueado para siempre.
	 */
	const LOCK_TRANSIENT = 'abh_journal_lock';
	const LOCK_TTL       = 15;
	const LOCK_WAIT      = 2;

	/**
	 * El almacén privado ya se preparó en esta petición.
	 *
	 * @var bool
	 */
	private static $almacen_listo = false;

	/**
	 * Cabecera de una copia guardada SIN cifrar, a propósito.
	 *
	 * Existe para que el formato sea declarado y no adivinado: `ABH1:` es el
	 * contenedor sellado, `ABH0:` es una copia en claro legítima escrita por un
	 * host sin sodium ni openssl, y cualquier otra cosa es un archivo corrupto
	 * que NO se escribe encima del sitio al revertir.
	 */
	const MARCA_CLARO = 'ABH0:';

	/**
	 * Sufijo aleatorio de la carpeta privada.
	 *
	 * @return string
	 */
	public static function storage_key() {
		$key = get_option( 'abh_storage_key', '' );
		if ( ! is_string( $key ) || ! preg_match( '/^[A-Za-z0-9_-]{12,64}$/', $key ) ) {
			$key = wp_generate_password( 24, false, false );
			update_option( 'abh_storage_key', $key, false );
		}
		return $key;
	}

	/**
	 * Base de subidas, sin crear la carpeta del mes al preguntar.
	 *
	 * @return string
	 */
	private static function uploads_basedir() {
		$up = function_exists( 'wp_get_upload_dir' ) ? wp_get_upload_dir() : wp_upload_dir();
		if ( ! is_array( $up ) || empty( $up['basedir'] ) ) {
			return '';
		}
		return rtrim( wp_normalize_path( (string) $up['basedir'] ), '/' );
	}

	/**
	 * Carpeta privada preferida.
	 *
	 * SIEMPRE dentro de la instalación de WordPress salvo que el dueño del
	 * servidor diga otra cosa con ABH_BACKUP_DIR. Esa constante se edita en
	 * wp-config.php, no se acepta desde el panel, y es la ÚNICA forma de sacar
	 * el almacén de aquí: es configuración consentida, no una decisión nuestra.
	 *
	 * Antes se elegía sola una carpeta HERMANA de ABSPATH en cuanto el padre
	 * fuera escribible, que en un cPanel normal —WordPress en public_html/— es
	 * el caso corriente. Crear archivos fuera de la instalación sin avisar es
	 * modificar el servidor sin permiso, y además rompía en silencio las copias
	 * y las migraciones del hosting, que solo se llevan la carpeta del sitio.
	 *
	 * Lo que sí se respeta es lo que ya existe: si una versión anterior dejó ahí
	 * fuera su carpeta, se sigue leyendo y escribiendo en ella. Dentro están los
	 * respaldos de este sitio, y mudarse de sitio los dejaría huérfanos y al
	 * dueño sin marcha atrás justo el día que la necesite.
	 *
	 * @return string
	 */
	public static function dir() {
		if ( defined( 'ABH_BACKUP_DIR' ) && is_string( ABH_BACKUP_DIR ) && '' !== trim( ABH_BACKUP_DIR ) ) {
			$dir = rtrim( wp_normalize_path( ABH_BACKUP_DIR ), '/' );
			update_option( 'abh_backup_dir', $dir, false );
			return $dir;
		}

		$key      = self::storage_key();
		$sufijo   = '/.ai-bug-hunter-private-' . $key;
		$wp_root  = rtrim( wp_normalize_path( ABSPATH ), '/' );
		$heredada = rtrim( wp_normalize_path( dirname( $wp_root ) ), '/' ) . $sufijo;

		// Candidatas nuevas, todas dentro de la instalación.
		$candidatas = array();
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$contenido = rtrim( wp_normalize_path( WP_CONTENT_DIR ), '/' );
			if ( '' !== $contenido ) {
				$candidatas[] = $contenido . $sufijo;
			}
		}
		$subidas = self::uploads_basedir();
		if ( '' !== $subidas ) {
			$candidatas[] = $subidas . $sufijo;
		}

		// 1) Manda la que ya existe, incluida la heredada de fuera de ABSPATH.
		$elegida = '';
		foreach ( array_merge( array( $heredada ), $candidatas ) as $candidata ) {
			if ( is_dir( $candidata ) && ! is_link( $candidata ) ) {
				$elegida = $candidata;
				break;
			}
		}
		// 2) Si no hay ninguna, se estrena dentro del sitio y NUNCA fuera.
		if ( '' === $elegida ) {
			foreach ( $candidatas as $candidata ) {
				$padre = dirname( $candidata );
				if ( is_dir( $padre ) && is_writable( $padre ) ) {
					$elegida = $candidata;
					break;
				}
			}
		}
		if ( '' === $elegida ) {
			$elegida = ! empty( $candidatas ) ? $candidatas[0] : $wp_root . '/wp-content' . $sufijo;
		}

		update_option( 'abh_backup_dir', $elegida, false );
		return $elegida;
	}

	/**
	 * Carpeta pública usada por versiones antiguas.
	 *
	 * @return string
	 */
	public static function legacy_dir() {
		$up = wp_upload_dir();
		return trailingslashit( $up['basedir'] ) . 'ai-bug-hunter-backups';
	}

	/**
	 * Carpeta aleatoria bajo uploads usada por 1.4.0.
	 *
	 * @return string
	 */
	private static function legacy_random_dir() {
		$up = wp_upload_dir();
		return trailingslashit( $up['basedir'] ) . 'ai-bug-hunter-backups-' . self::storage_key();
	}

	/**
	 * Directorios que el componente puede leer o borrar.
	 *
	 * @return array
	 */
	private static function known_dirs() {
		$dirs = array( self::dir(), self::legacy_dir(), self::legacy_random_dir() );
		return array_values( array_unique( array_map( static function ( $dir ) {
			return rtrim( wp_normalize_path( (string) $dir ), '/' );
		}, $dirs ) ) );
	}

	/**
	 * Comprueba que un archivo pertenece a una carpeta de respaldos conocida.
	 *
	 * @param string $path Ruta.
	 * @return bool
	 */
	private static function is_known_backup_path( $path ) {
		$path = wp_normalize_path( (string) $path );
		if ( '' === $path || is_link( $path ) || ! file_exists( $path ) ) {
			return false;
		}
		$real = realpath( $path );
		if ( false === $real ) {
			return false;
		}
		$real = wp_normalize_path( $real );
		foreach ( self::known_dirs() as $dir ) {
			if ( is_link( $dir ) ) {
				continue;
			}
			$dir_real = realpath( $dir );
			if ( false !== $dir_real && hash_equals( rtrim( wp_normalize_path( $dir_real ), '/' ), rtrim( wp_normalize_path( dirname( $real ) ), '/' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Escribe un contenedor nuevo con creación exclusiva y confirma que la
	 * carpeta de destino sigue siendo la carpeta privada real del plugin.
	 *
	 * @param string $dest Destino nuevo.
	 * @param string $data Datos sellados.
	 * @return bool
	 */
	private static function write_private_file( $dest, $data ) {
		$dir      = self::dir();
		$dir_real = ! is_link( $dir ) ? realpath( $dir ) : false;
		if ( false === $dir_real || rtrim( wp_normalize_path( dirname( $dest ) ), '/' ) !== rtrim( wp_normalize_path( $dir ), '/' ) ) {
			return false;
		}
		$fh = @fopen( $dest, 'x+b' );
		if ( false === $fh ) {
			return false;
		}
		$bytes = (string) $data;
		$left  = strlen( $bytes );
		$off   = 0;
		$ok    = true;
		while ( $left > 0 ) {
			$wrote = @fwrite( $fh, substr( $bytes, $off, min( 1048576, $left ) ) );
			if ( false === $wrote || 0 === $wrote ) {
				$ok = false;
				break;
			}
			$off  += $wrote;
			$left -= $wrote;
		}
		@fflush( $fh );
		if ( function_exists( 'fsync' ) ) {
			@fsync( $fh );
		}
		@fclose( $fh );
		@chmod( $dest, 0600 );

		$dir_recheck = ! is_link( $dir ) ? realpath( $dir ) : false;
		if ( ! $ok || false === $dir_recheck || ! hash_equals( wp_normalize_path( $dir_real ), wp_normalize_path( $dir_recheck ) ) || is_link( $dest ) ) {
			@unlink( $dest );
			return false;
		}
		return true;
	}

	/**
	 * Carpetas del sitio que JAMÁS pueden ser la raíz del almacén.
	 *
	 * @return array
	 */
	private static function reserved_roots() {
		$rutas = array( ABSPATH );
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$rutas[] = WP_CONTENT_DIR;
		}
		$subidas = self::uploads_basedir();
		if ( '' !== $subidas ) {
			$rutas[] = $subidas;
		}

		$salida = array();
		foreach ( $rutas as $ruta ) {
			$ruta = rtrim( wp_normalize_path( (string) $ruta ), '/' );
			if ( '' === $ruta ) {
				continue;
			}
			$real = realpath( $ruta );
			if ( false !== $real ) {
				$ruta = rtrim( wp_normalize_path( $real ), '/' );
			}
			if ( '' !== $ruta ) {
				$salida[] = $ruta;
			}
		}
		return array_values( array_unique( $salida ) );
	}

	/**
	 * Resuelve la raíz del almacén y se niega a devolverla si es una carpeta
	 * del sitio o está por encima de una.
	 *
	 * ABH_BACKUP_DIR llegaba hasta los bucles de borrado sin que nadie mirase a
	 * dónde apunta. Apuntada a ABSPATH —o a cualquier carpeta que contenga
	 * ABSPATH, wp-content o las subidas—, una purga se llevaba por delante el
	 * index.php y el .htaccess del propio WordPress. Aquí se corta antes: si la
	 * raíz configurada no es una carpeta propia, no se opera en absoluto.
	 *
	 * @param string $dir Carpeta candidata.
	 * @return string|false Ruta resuelta, o false si no se puede tocar.
	 */
	private static function safe_storage_root( $dir ) {
		$dir = rtrim( wp_normalize_path( (string) $dir ), '/' );
		if ( '' === $dir || is_link( $dir ) ) {
			return false;
		}
		$real = realpath( $dir );
		if ( false === $real ) {
			return false;
		}
		$real = rtrim( wp_normalize_path( $real ), '/' );
		if ( '' === $real || '/' === $real ) {
			return false;
		}
		foreach ( self::reserved_roots() as $reservada ) {
			// La misma carpeta, o una que la contiene: en ambos casos, fuera.
			if ( $real === $reservada || 0 === strpos( $reservada, $real . '/' ) ) {
				return false;
			}
		}
		return $real;
	}

	/**
	 * ¿Cuelga realmente $path de $root una vez resueltos los dos?
	 *
	 * @param string $path Ruta.
	 * @param string $root Raíz resuelta.
	 * @return bool
	 */
	private static function path_inside( $path, $root ) {
		$path = rtrim( wp_normalize_path( (string) $path ), '/' );
		$root = rtrim( wp_normalize_path( (string) $root ), '/' );
		if ( '' === $path || '' === $root || is_link( $path ) || is_link( $root ) ) {
			return false;
		}
		$path_real = realpath( $path );
		$root_real = realpath( $root );
		if ( false === $path_real || false === $root_real ) {
			return false;
		}
		$path_real = rtrim( wp_normalize_path( $path_real ), '/' );
		$root_real = rtrim( wp_normalize_path( $root_real ), '/' );
		return 0 === strpos( $path_real, $root_real . '/' );
	}

	/**
	 * Blindaje que este plugin escribe dentro de su carpeta privada.
	 *
	 * Se declara en un solo sitio porque la purga borraba estos tres nombres a
	 * ciegas. Comparando el contenido exacto solo se borra lo que escribimos
	 * nosotros, nunca el index.php ni el .htaccess de otra carpeta.
	 *
	 * @return array Nombre => contenido.
	 */
	private static function hardening_files() {
		return array(
			'.htaccess'  => "# BEGIN AI Bug Hunter\n"
				. "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
				. "<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n"
				. "Options -Indexes\n# END AI Bug Hunter\n",
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
			'index.php'  => "<?php\n// Silence is golden.\n",
		);
	}

	/**
	 * ¿Es este archivo de blindaje uno de los nuestros?
	 *
	 * @param string $file Ruta completa.
	 * @param string $name Nombre base.
	 * @return bool
	 */
	private static function is_own_hardening_file( $file, $name ) {
		$blindaje = self::hardening_files();
		if ( ! isset( $blindaje[ $name ] ) ) {
			return false;
		}
		$size = @filesize( $file );
		if ( false === $size || $size > 4096 ) {
			return false;
		}
		$actual = (string) @file_get_contents( $file );
		if ( '.htaccess' === $name ) {
			// Las reglas pueden venir de una versión anterior; la marca no.
			return 0 === strpos( $actual, '# BEGIN AI Bug Hunter' );
		}
		return hash_equals( $blindaje[ $name ], $actual );
	}

	/**
	 * Respaldos propios que una purga puede eliminar.
	 *
	 * El blindaje ya NO entra por nombre: lo decide is_own_hardening_file()
	 * comparando el contenido.
	 *
	 * @param string $name Nombre base.
	 * @return bool
	 */
	private static function removable_name( $name ) {
		return (bool) preg_match( '/^[a-f0-9]{12,64}__[^\/]+\.(?:abhbak|txt|bak|php|phtml)$/i', (string) $name );
	}

	/**
	 * ¿Estamos dentro del gancho de activación del plugin?
	 *
	 * @return bool
	 */
	private static function en_activacion() {
		if ( function_exists( 'wp_installing' ) && wp_installing() ) {
			return true;
		}
		if ( ! defined( 'ABH_FILE' ) || ! function_exists( 'doing_action' ) ) {
			return false;
		}
		return (bool) doing_action( 'activate_' . plugin_basename( ABH_FILE ) );
	}

	/**
	 * Prepara el almacenamiento privado, la primera vez que hace falta de verdad.
	 *
	 * ACTIVAR NO ESCRIBE NADA. Crear carpetas y archivos porque alguien pulsó
	 * «Activar» es tocar el sitio sin que nadie lo haya pedido, y encima es
	 * trabajo tirado en la enorme mayoría de instalaciones, que nunca llegan a
	 * guardar un respaldo. El almacén se estrena cuando hay un respaldo que
	 * guardar —snapshot(), la caché del núcleo, el laboratorio— y no antes.
	 *
	 * @return bool
	 */
	public static function prepare_storage() {
		if ( self::en_activacion() ) {
			return true;
		}
		if ( self::$almacen_listo ) {
			return true;
		}
		// Sin cifrado disponible NO se aborta. Rendirse aquí tumbaba el producto
		// entero en ese host: sin respaldo no hay snapshot, sin snapshot no hay
		// reparación, y encima tampoco había reversión. Un sitio roto en un
		// hosting viejo se quedaba sin la herramienta justo cuando la necesita.
		// Lo que protege estas copias no es el sobre: es la carpeta —privada,
		// 0700, con .htaccess, web.config e index.php, y cada archivo en
		// 0600—. Cuando hay con qué sellar se sella; cuando no,
		// se guarda en claro con la marca ABH0:. Y se declara en pantalla: las
		// capacidades de ABH_Limits dicen «cifrado si el servidor lo permite»,
		// no «cifrado» a secas, porque prometer un sobre que a veces no existe
		// es la clase de mentira que este producto no se puede permitir.
		$dir = self::dir();
		if ( is_link( $dir ) ) {
			return false;
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return false;
		}
		@chmod( $dir, 0700 );

		// La raíz se comprueba con la carpeta YA creada: una ABH_BACKUP_DIR que
		// resuelva a ABSPATH, a wp-content, a las subidas o a cualquier carpeta
		// que las contenga no es un almacén, es el sitio entero. Ahí no se
		// blinda, no se migra y no se guarda nada.
		if ( false === self::safe_storage_root( $dir ) ) {
			return false;
		}

		// Defensa adicional: el almacén vive bajo el webroot salvo que el dueño
		// lo mueva a mano, así que el servidor tiene que negarlo por su cuenta.
		foreach ( self::hardening_files() as $nombre => $contenido ) {
			$destino = $dir . '/' . $nombre;
			if ( ! file_exists( $destino ) ) {
				@file_put_contents( $destino, $contenido, LOCK_EX );
				@chmod( $destino, 0600 );
			}
		}

		self::$almacen_listo = true;
		self::migrate_legacy();
		return true;
	}

	/**
	 * Migra respaldos antiguos de texto plano al contenedor cifrado.
	 *
	 * @return void
	 */
	public static function migrate_legacy() {
		if ( '1' === get_option( 'abh_storage_migrated_v2', '' ) ) {
			return;
		}
		if ( ! ABH_Crypto::available() ) {
			return;
		}

		$new_dir = self::dir();
		$map     = array();
		foreach ( array( self::legacy_dir(), self::legacy_random_dir() ) as $old_dir ) {
			$old_dir = rtrim( wp_normalize_path( $old_dir ), '/' );
			if ( $old_dir === $new_dir || ! is_dir( $old_dir ) || is_link( $old_dir ) ) {
				continue;
			}
			$files = glob( $old_dir . '/*__*' );
			if ( ! is_array( $files ) ) {
				continue;
			}
			foreach ( $files as $source ) {
				if ( ! is_file( $source ) || is_link( $source ) ) {
					continue;
				}
				$plain = (string) @file_get_contents( $source );
				if ( ABH_Crypto::is_encrypted( $plain ) ) {
					$decoded = ABH_Crypto::decrypt( $plain, 'backup' );
					if ( false === $decoded ) {
						continue;
					}
					$plain = $decoded;
				}
				$sealed = ABH_Crypto::encrypt( $plain, 'backup' );
				if ( false === $sealed ) {
					continue;
				}
				$name = preg_replace( '/\.(?:php|phtml|txt|bak)$/i', '', basename( $source ) ) . '.abhbak';
				$dest = $new_dir . '/' . $name;
				if ( self::write_private_file( $dest, $sealed ) ) {
					$map[ basename( $source ) ] = $dest;
					@unlink( $source );
				}
			}
		}

		if ( ! empty( $map ) ) {
			$movido = self::update_journal(
				static function ( $journal ) use ( $map ) {
					foreach ( $journal as $i => $op ) {
						$name = ! empty( $op['backup_file'] ) ? basename( $op['backup_file'] ) : '';
						if ( isset( $map[ $name ] ) ) {
							$journal[ $i ]['backup_file'] = $map[ $name ];
						}
					}
					return $journal;
				}
			);
			// Sin repuntar el diario NO se da la migración por hecha: se
			// reintenta en la próxima petición en vez de dejar las filas
			// apuntando a archivos que ya no están donde dicen.
			if ( empty( $movido['ok'] ) ) {
				return;
			}
		}
		update_option( 'abh_storage_migrated_v2', '1', false );
	}

	/** @return array */
	public static function journal() {
		$j = get_option( self::OPTION_JOURNAL, array() );
		return is_array( $j ) ? $j : array();
	}

	/**
	 * Toma el candado del diario, o se rinde a tiempo.
	 *
	 * Se escribe y se relee: si otro proceso metió el suyo en ese microsegundo,
	 * gana él y aquí se sigue esperando. No se espera eternamente —dos segundos
	 * como mucho— porque esto corre dentro de una petición de administración y
	 * colgarla es peor que no escribir la fila.
	 *
	 * @return string|false Testigo del candado, o false si no se consiguió.
	 */
	private static function journal_lock() {
		$testigo = wp_generate_password( 24, false, false );
		$limite  = microtime( true ) + (float) self::LOCK_WAIT;
		do {
			$actual = get_transient( self::LOCK_TRANSIENT );
			if ( false === $actual || ! is_string( $actual ) || '' === $actual ) {
				set_transient( self::LOCK_TRANSIENT, $testigo, self::LOCK_TTL );
				$confirma = get_transient( self::LOCK_TRANSIENT );
				if ( is_string( $confirma ) && hash_equals( $testigo, $confirma ) ) {
					return $testigo;
				}
			}
			// Con algo de azar para que dos procesos no reboten a la vez.
			usleep( 25000 + wp_rand( 0, 25000 ) );
		} while ( microtime( true ) < $limite );
		return false;
	}

	/**
	 * Suelta el candado, y solo si sigue siendo el nuestro.
	 *
	 * @param string $testigo Testigo devuelto por journal_lock().
	 * @return void
	 */
	private static function journal_unlock( $testigo ) {
		$actual = get_transient( self::LOCK_TRANSIENT );
		if ( is_string( $actual ) && hash_equals( (string) $testigo, $actual ) ) {
			delete_transient( self::LOCK_TRANSIENT );
		}
	}

	/**
	 * Mensaje de un diario ocupado.
	 *
	 * @return string
	 */
	private static function journal_busy_message() {
		return __( 'The history is busy: another repair is writing to it right now, and nothing was recorded. Wait a moment and try again.', 'ai-bug-hunter' );
	}

	/**
	 * Modifica el diario en exclusiva.
	 *
	 * El diario se relee DENTRO del candado, y a propósito se tira antes la
	 * copia en caché: leer la lista de antes y escribirla encima es justo la
	 * carrera que esto viene a cerrar.
	 *
	 * @param callable $mutador Recibe el diario y devuelve el diario nuevo, o false para no escribir.
	 * @return array ok, message, changed.
	 */
	private static function update_journal( $mutador ) {
		$testigo = self::journal_lock();
		if ( false === $testigo ) {
			$mensaje = self::journal_busy_message();
			// Que no se pierda: la fila no se escribió y alguien tiene que verlo.
			set_transient( 'abh_journal_error', $mensaje, HOUR_IN_SECONDS );
			return array( 'ok' => false, 'message' => $mensaje, 'changed' => false );
		}

		wp_cache_delete( self::OPTION_JOURNAL, 'options' );
		$nuevo = call_user_func( $mutador, self::journal() );
		if ( ! is_array( $nuevo ) ) {
			self::journal_unlock( $testigo );
			return array( 'ok' => true, 'message' => '', 'changed' => false );
		}
		update_option( self::OPTION_JOURNAL, $nuevo, false );
		self::journal_unlock( $testigo );
		return array( 'ok' => true, 'message' => '', 'changed' => true );
	}

	/**
	 * @param string $op_id Identificador.
	 * @return array|false
	 */
	public static function get( $op_id ) {
		foreach ( self::journal() as $op ) {
			if ( isset( $op['op_id'] ) && hash_equals( (string) $op['op_id'], (string) $op_id ) ) {
				return $op;
			}
		}
		return false;
	}

	/**
	 * Guarda un respaldo: cifrado y autenticado cuando el servidor tiene con qué
	 * sellarlo, y en claro con la marca ABH0: cuando no. Lo que protege la copia
	 * en ese segundo caso es la carpeta —privada, 0700, blindada—, no el sobre.
	 *
	 * @param string $rel_path Ruta relativa.
	 * @param string $content  Original.
	 * @return array|false
	 */
	public static function snapshot( $rel_path, $content ) {
		if ( ! self::prepare_storage() ) {
			return false;
		}
		// Se sella si se puede; si no, se guarda en claro CON SU PROPIA MARCA.
		//
		// El prefijo importa: sin él, «no empieza por ABH1:» significaba a la vez
		// «lo guardó un host sin cifrado» y «este archivo está corrupto», y
		// read_backup() no podía distinguirlos. Un respaldo con los primeros
		// bytes estropeados —un rsync a medias, la herramienta de copia del
		// hosting— se habría escrito verbatim sobre el archivo vivo del sitio al
		// revertir. Con ABH0: el formato vuelve a ser declarado, no adivinado.
		$sellado = ABH_Crypto::available() ? ABH_Crypto::encrypt( (string) $content, 'backup' ) : false;
		$sealed  = ( false === $sellado ) ? self::MARCA_CLARO . (string) $content : $sellado;
		$op_id = substr( hash( 'sha256', $rel_path . microtime( true ) . wp_rand() ), 0, 16 );
		$safe  = preg_replace( '/[^A-Za-z0-9._-]/', '_', $rel_path );
		$dest  = self::dir() . '/' . $op_id . '__' . substr( $safe, -80 ) . '.abhbak';
		if ( ! self::write_private_file( $dest, $sealed ) ) {
			return false;
		}
		return array( 'op_id' => $op_id, 'file' => $dest );
	}

	/**
	 * @param array $op Operación.
	 * @return array
	 */
	public static function record( $op ) {
		$defaults = array(
			'op_id' => '', 'ts' => current_time( 'mysql' ), 'ts_unix' => time(), 'action' => 'write',
			'rel_path' => '', 'incident_key' => '', 'abs_path' => '', 'sha_before' => '', 'sha_after' => '',
			'backup_file' => '', 'mode_before' => 0, 'mode_after' => 0, 'status' => 'applied', 'model' => '',
			'incident' => '', 'diagnosis' => '', 'explicacion' => array(), 'usage' => array(),
			'user' => get_current_user_id(), 'findings' => array(),
		);
		$op = wp_parse_args( $op, $defaults );

		$escrito = self::update_journal(
			static function ( $journal ) use ( $op ) {
				array_unshift( $journal, $op );
				if ( count( $journal ) > self::MAX_ENTRIES ) {
					$removed = array_slice( $journal, self::MAX_ENTRIES );
					$journal = array_slice( $journal, 0, self::MAX_ENTRIES );
					foreach ( $removed as $old ) {
						if ( ! empty( $old['backup_file'] ) && self::is_known_backup_path( $old['backup_file'] ) ) {
							@unlink( $old['backup_file'] );
						}
					}
				}
				return $journal;
			}
		);

		// Si el diario estaba ocupado la fila NO se escribió, y esa fila es la
		// única que sabe dónde quedó el respaldo. Se dice, no se traga.
		if ( empty( $escrito['ok'] ) ) {
			$op['journal_error'] = $escrito['message'];
		}
		return $op;
	}

	/**
	 * Archiva el registro de la consola dentro de la operación del historial.
	 *
	 * Permite recuperar más tarde "qué hizo HUNTER" aunque el trabajo cifrado ya
	 * haya caducado. Se guarda como texto plano acotado, no como HTML.
	 *
	 * @param string $op_id  Identificador de operación o de transacción.
	 * @param array  $events Eventos de la consola.
	 * @return bool
	 */
	public static function attach_console_log( $op_id, $events ) {
		$lines = array();
		foreach ( array_slice( (array) $events, 0, 400 ) as $e ) {
			if ( ! is_array( $e ) ) {
				continue;
			}
			$time   = isset( $e['time'] ) ? sanitize_text_field( (string) $e['time'] ) : '';
			$type   = isset( $e['type'] ) ? sanitize_key( (string) $e['type'] ) : 'info';
			$title  = isset( $e['title'] ) ? wp_strip_all_tags( (string) $e['title'] ) : '';
			$detail = isset( $e['detail'] ) ? wp_strip_all_tags( (string) $e['detail'] ) : '';
			$code   = isset( $e['code'] ) ? wp_strip_all_tags( (string) $e['code'] ) : '';
			$line   = '[' . $time . '] [' . strtoupper( $type ) . '] ' . $title;
			if ( '' !== $detail ) {
				$line .= "\n  " . $detail;
			}
			if ( '' !== $code ) {
				$line .= "\n  " . $code;
			}
			$lines[] = substr( $line, 0, 4000 );
		}
		if ( empty( $lines ) ) {
			return false;
		}
		$text = substr( implode( "\n\n", $lines ), 0, 262144 );

		$escrito = self::update_journal(
			static function ( $journal ) use ( $op_id, $text ) {
				$hit = false;
				foreach ( $journal as $i => $op ) {
					$matches_op  = isset( $op['op_id'] ) && hash_equals( (string) $op['op_id'], (string) $op_id );
					$matches_txn = isset( $op['txn_id'] ) && '' !== (string) $op['txn_id'] && hash_equals( (string) $op['txn_id'], (string) $op_id );
					if ( $matches_op || $matches_txn ) {
						$journal[ $i ]['console_log'] = $text;
						$hit                          = true;
					}
				}
				return $hit ? $journal : false;
			}
		);
		return ! empty( $escrito['ok'] ) && ! empty( $escrito['changed'] );
	}

	/**
	 * Cambia el estado de una operación del historial.
	 *
	 * @param string $op_id  Identificador.
	 * @param string $status Estado nuevo.
	 * @return bool Si llegó a escribirse.
	 */
	public static function set_status( $op_id, $status ) {
		$estado  = sanitize_key( $status );
		$escrito = self::update_journal(
			static function ( $journal ) use ( $op_id, $estado ) {
				$hit = false;
				foreach ( $journal as $i => $op ) {
					if ( isset( $op['op_id'] ) && hash_equals( (string) $op['op_id'], (string) $op_id ) ) {
						$journal[ $i ]['status'] = $estado;
						$hit                     = true;
					}
				}
				return $hit ? $journal : false;
			}
		);
		return ! empty( $escrito['ok'] ) && ! empty( $escrito['changed'] );
	}

	/** @return int */
	public static function op_unix( $op ) {
		if ( ! empty( $op['ts_unix'] ) ) {
			return (int) $op['ts_unix'];
		}
		if ( ! empty( $op['ts'] ) ) {
			$gmt = get_gmt_from_date( $op['ts'] );
			$u = strtotime( $gmt . ' UTC' );
			return $u ? (int) $u : 0;
		}
		return 0;
	}

	/** @return array|false */
	public static function last_applied_for( $rel_path, $incident_key = '' ) {
		if ( '' === $rel_path && '' === $incident_key ) {
			return false;
		}
		$best = false;
		foreach ( self::journal() as $op ) {
			if ( empty( $op['status'] ) || 'applied' !== $op['status'] ) {
				continue;
			}
			$match = ( '' !== $rel_path && ! empty( $op['rel_path'] ) && $op['rel_path'] === $rel_path )
				|| ( '' !== $incident_key && ! empty( $op['incident_key'] ) && $op['incident_key'] === $incident_key );
			if ( $match && ( false === $best || self::op_unix( $op ) > self::op_unix( $best ) ) ) {
				$best = $op;
			}
		}
		return $best;
	}

	/**
	 * @param string $saved Ruta guardada.
	 * @return string|false
	 */
	public static function locate_backup( $saved ) {
		$name = basename( (string) $saved );
		if ( '' === $name || ! preg_match( '/^[A-Za-z0-9._-]+$/', $name ) ) {
			return false;
		}
		$base = preg_replace( '/\.(?:php|phtml|txt|bak|abhbak)$/i', '', $name );
		$candidates = array( $name, $name . '.abhbak', $name . '.txt', $base . '.abhbak', $base . '.txt' );
		foreach ( self::known_dirs() as $dir ) {
			foreach ( array_unique( $candidates ) as $candidate ) {
				$path = $dir . '/' . $candidate;
				if ( self::is_known_backup_path( $path ) && is_file( $path ) && is_readable( $path ) ) {
					return $path;
				}
			}
		}
		return false;
	}

	/**
	 * Lee y autentica un respaldo. Se tolera texto plano solo para migraciones
	 * antiguas y únicamente dentro de las carpetas legacy conocidas.
	 *
	 * @param string $path Ruta.
	 * @return string|false
	 */
	public static function read_backup( $path ) {
		if ( ! self::is_known_backup_path( $path ) || ! is_file( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		$stored = (string) @file_get_contents( $path );
		// Una copia sin sellar es legítima SÓLO si ella misma lo declara. La
		// escribió un host sin sodium ni openssl, y lleva su marca. Todo lo
		// demás que no sea un contenedor ABH1: es un archivo corrupto o
		// manipulado, y sigue rechazándose como siempre: esto se escribe encima
		// del archivo vivo del sitio al revertir, así que aceptar cualquier cosa
		// que «no parezca cifrada» era abrir la puerta entera para tapar un
		// hueco que sólo existía en los hosts sin cifrado.
		if ( 0 === strpos( $stored, self::MARCA_CLARO ) ) {
			return substr( $stored, strlen( self::MARCA_CLARO ) );
		}
		if ( ! ABH_Crypto::is_encrypted( $stored ) ) {
			return false;
		}
		return ABH_Crypto::decrypt( $stored, 'backup' );
	}

	/**
	 * Nombre legible de quien aplicó una operación.
	 *
	 * @param int $user_id Identificador.
	 * @return string
	 */
	private static function user_label( $user_id ) {
		$u = function_exists( 'get_userdata' ) ? get_userdata( (int) $user_id ) : false;
		if ( $u && isset( $u->display_name ) && '' !== (string) $u->display_name ) {
			return (string) $u->display_name;
		}
		/* translators: %d: identificador del usuario. */
		return sprintf( __( 'another administrator (ID %d)', 'ai-bug-hunter' ), (int) $user_id );
	}

	/**
	 * ¿Es de esta persona lo que va a deshacer?
	 *
	 * El plugin ata cada cosa a quien la empezó —los trabajos de THOTH, las
	 * propuestas pendientes, los escaneos, los permisos de entorno aprobados, la
	 * firma del modo root— y el Historial era el único sitio donde no se
	 * miraba: con la capacidad puesta, cualquiera podía revertir la operación de
	 * otro, incluida una que se estuviera aplicando en ese mismo momento. Aquí
	 * el candado no es la integridad del archivo: sha_before y sha_after dicen
	 * si el CONTENIDO cambió, nunca de quién era el trabajo.
	 *
	 * No se cierra del todo, y eso NO es un descuido: el encabezado de este
	 * archivo declara que impedir que un administrador revierta lo que aplicó
	 * otro mata el caso de agencia, que es lo normal y no la excepción. Así que
	 * se ata en dos niveles, según lo que de verdad se esté pisando:
	 *
	 *  · Ajena y TODAVÍA EN VUELO —la transacción sigue aplicándose, o su vuelta
	 *    atrás quedó a medias—: se rechaza sin salida. Deshacer por debajo de
	 *    quien está escribiendo ahora mismo no es una decisión, es una carrera
	 *    contra el disco, y la pierde el sitio.
	 *  · Ajena y ya terminada: se pide la MISMA confirmación explícita que ya
	 *    existe cuando el archivo cambió después ($force), diciendo de quién
	 *    era. Se puede, pero no por accidente y no sin enterarse de a quién se
	 *    le está deshaciendo el trabajo.
	 *
	 * Los asientos anteriores a esta versión pueden no traer autor. No se
	 * inventa uno: sin dato no hay dueño al que respetar.
	 *
	 * @param string $op_id Operación, o transacción completa.
	 * @param bool   $force Confirmación explícita de quien la pide.
	 * @return array|false Respuesta de rechazo, o false si puede seguir.
	 */
	private static function ownership_block( $op_id, $force ) {
		$op_id = (string) $op_id;
		if ( '' === $op_id ) {
			return false;
		}
		$mio   = get_current_user_id();
		$ajena = 0;
		$txn   = '';
		foreach ( self::journal() as $op ) {
			// Se mira el conjunto entero: un identificador TXN- no tiene un solo
			// asiento, y bastaría con que UNO de sus archivos fuera de otra
			// persona para que revertir el lote le pisara el trabajo.
			$suya = ( isset( $op['op_id'] ) && hash_equals( (string) $op['op_id'], $op_id ) )
				|| ( isset( $op['txn_id'] ) && '' !== (string) $op['txn_id'] && hash_equals( (string) $op['txn_id'], $op_id ) );
			if ( ! $suya || ( isset( $op['status'] ) && 'rolled_back' === $op['status'] ) ) {
				continue;
			}
			if ( '' === $txn && ! empty( $op['txn_id'] ) ) {
				$txn = (string) $op['txn_id'];
			}
			$quien = isset( $op['user'] ) ? (int) $op['user'] : 0;
			if ( 0 === $ajena && $quien > 0 && $quien !== $mio ) {
				$ajena = $quien;
			}
		}
		if ( 0 === $ajena ) {
			return false;
		}

		if ( '' !== $txn && class_exists( 'ABH_Health' ) && ABH_Health::transaccion_en_vuelo( $txn ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: administrador que la está aplicando. */
					__( '%s has that repair in hand right now. Wait until it finishes: reverting it underneath would leave some files patched and others not, without either side knowing.', 'ai-bug-hunter' ),
					self::user_label( $ajena )
				),
			);
		}

		if ( $force ) {
			return false;
		}
		return array(
			'ok'          => false,
			'needs_force' => true,
			'message'     => sprintf(
				/* translators: %s: administrador que aplicó el cambio. */
				__( 'This change was applied by %s, not by you. You can still revert it —two people taking turns on the same site is normal—, but confirm it: whoever applied it will not find out.', 'ai-bug-hunter' ),
				self::user_label( $ajena )
			),
		);
	}

	/**
	 * @param string $op_id Identificador.
	 * @param bool   $force Forzar si cambió después.
	 * @return array
	 */
	public static function rollback( $op_id, $force = false ) {
		// De quién es esto se pregunta ANTES de mirar la ruta, el respaldo o el
		// hash, y antes de repartir hacia la transacción: si la respuesta es que
		// no, no hay ningún motivo para haber tocado nada por el camino.
		$ajena = self::ownership_block( $op_id, $force );
		if ( false !== $ajena ) {
			return $ajena;
		}
		// Un identificador de transacción revierte el conjunto completo.
		if ( 0 === strpos( (string) $op_id, 'TXN-' ) ) {
			return self::rollback_transaction( (string) $op_id, $force );
		}
		$op = self::get( $op_id );
		if ( ! $op ) {
			return array( 'ok' => false, 'message' => __( 'That operation was not found in the history.', 'ai-bug-hunter' ) );
		}
		if ( 'rolled_back' === $op['status'] ) {
			return array( 'ok' => false, 'message' => __( 'That operation was already reverted.', 'ai-bug-hunter' ) );
		}

		// Restauración de un archivo del núcleo: se resuelve ANTES que la ruta
		// genérica, porque las raíces escribibles del motor solo cubren
		// wp-content y un archivo del núcleo nunca pasaría ese filtro. Aquí el
		// permiso lo concede el manifiesto oficial de WordPress, que es una
		// lista blanca más estricta, no más laxa.
		if ( isset( $op['action'] ) && 'core_restore' === $op['action'] && class_exists( 'ABH_Core' ) ) {
			$backup = ! empty( $op['backup_file'] ) ? self::locate_backup( $op['backup_file'] ) : false;
			if ( ! $backup ) {
				return array( 'ok' => false, 'message' => __( 'The backup for that restore is missing.', 'ai-bug-hunter' ) );
			}
			$original = self::read_backup( $backup );
			if ( false === $original ) {
				return array( 'ok' => false, 'message' => __( 'The backup could not be authenticated. Nothing was written.', 'ai-bug-hunter' ) );
			}
			$abs_core = ABH_Core::core_path( isset( $op['rel_path'] ) ? $op['rel_path'] : '' );
			if ( ! $abs_core ) {
				return array( 'ok' => false, 'message' => __( 'That path is no longer part of the core of the installed version.', 'ai-bug-hunter' ) );
			}
			$vuelta = ABH_Core::write_core_file( $abs_core, $original );
			if ( empty( $vuelta['ok'] ) ) {
				return $vuelta;
			}
			self::set_status( $op_id, 'rolled_back' );
			return array( 'ok' => true, 'message' => sprintf( /* translators: %s: restored relative file path. */ __( 'Restore undone: %s went back to its previous content.', 'ai-bug-hunter' ), $op['rel_path'] ) );
		}

		$rel = isset( $op['rel_path'] ) ? ABH_Guard::normalize( $op['rel_path'] ) : '';

		// UN DROP-IN SE PUEDE DESHACER, aunque ya no se pueda escribir.
		//
		// `check_path()` niega los drop-ins desde que la regla se movió allí, y
		// eso dejó sin marcha atrás las entradas de historial que una versión
		// ANTERIOR sí llegó a escribir. Es justo el caso en que más falta hace:
		// el plugin puso un `wp-content/object-cache.php` que no debía, y al
		// pedirle que lo retire contesta que esa ruta está protegida. Quitar el
		// deshacer de algo que uno mismo hizo no es una defensa; es dejar al
		// dueño con el problema y sin la herramienta.
		//
		// Revertir no escribe contenido nuevo: devuelve los bytes que ESTE
		// plugin guardó antes de tocar nada, y eso no concede ninguna
		// capacidad. Es el mismo criterio que dejó volver a borrar un
		// `.htaccess` de malware. El ALCANCE sí se sigue comprobando, a mano,
		// para que la reversión no pueda salirse de las carpetas autorizadas.
		$dropin = '' !== $rel && class_exists( 'ABH_Limits' ) && ABH_Limits::is_dropin( $rel );

		if ( $dropin ) {
			// Con `null` se salta la regla de rutas pero NO la resolución: sigue
			// exigiendo que la ruta exista, rechaza enlaces y no deja salir de
			// ABSPATH.
			$abs = ABH_Guard::resolve_existing_path( $rel, null );
			if ( $abs ) {
				$dentro = false;
				foreach ( ABH_Engine::writable_roots() as $raiz ) {
					if ( ABH_Guard::path_in_root( $rel, $raiz ) ) {
						$dentro = true;
						break;
					}
				}
				if ( ! $dentro ) {
					$abs = false;
				}
			}
		} else {
			$abs = '' !== $rel ? ABH_Guard::resolve_existing_path( $rel, ABH_Engine::writable_roots() ) : false;
		}

		// `is_off_limits()` pregunta por `check_path()` a su vez, así que para un
		// drop-in diría que no por la misma razón y volvería a cerrar la puerta
		// que estas líneas acaban de abrir.
		if ( ! $abs || ( ! $dropin && ABH_Motor::is_off_limits( $abs ) ) ) {
			return array( 'ok' => false, 'message' => __( 'The path for that operation is no longer valid or is protected.', 'ai-bug-hunter' ) );
		}

		if ( isset( $op['action'] ) && 'chmod' === $op['action'] ) {
			if ( ! isset( $op['mode_before'] ) || ! is_numeric( $op['mode_before'] ) ) {
				return array( 'ok' => false, 'message' => __( 'The history does not contain valid previous permissions.', 'ai-bug-hunter' ) );
			}
			$mode = (int) $op['mode_before'];
			if ( $mode < 0 || $mode > 0777 || ! @chmod( $abs, $mode ) ) {
				return array( 'ok' => false, 'message' => __( 'The server did not allow the previous permissions to be restored.', 'ai-bug-hunter' ) );
			}
			clearstatcache( true, $abs );
			$restored = @fileperms( $abs );
			$restored = false !== $restored ? ( $restored & 0777 ) : -1;
			if ( $restored !== $mode ) {
				return array( 'ok' => false, 'message' => __( 'The server reported success, but the previous permissions were not restored.', 'ai-bug-hunter' ) );
			}
			self::set_status( $op_id, 'rolled_back' );
			return array( 'ok' => true, 'message' => sprintf( /* translators: 1: relative file path, 2: restored octal permissions. */ __( 'Permissions restored: %1$s is back to %2$s.', 'ai-bug-hunter' ), $rel, substr( sprintf( '%o', $mode ), -3 ) ) );
		}

		$backup = ! empty( $op['backup_file'] ) ? self::locate_backup( $op['backup_file'] ) : false;
		if ( ! $backup ) {
			return array( 'ok' => false, 'message' => __( 'The backup is missing. It cannot be reverted safely.', 'ai-bug-hunter' ) );
		}
		$original = self::read_backup( $backup );
		if ( false === $original ) {
			return array( 'ok' => false, 'message' => __( 'The backup could not be authenticated or decrypted. Nothing was written.', 'ai-bug-hunter' ) );
		}

		$actual = hash( 'sha256', (string) @file_get_contents( $abs ) );
		if ( ! empty( $op['sha_before'] ) && hash_equals( $op['sha_before'], $actual ) ) {
			self::set_status( $op_id, 'rolled_back' );
			return array( 'ok' => true, 'message' => __( 'The file was already in its original state.', 'ai-bug-hunter' ) );
		}
		if ( ! empty( $op['sha_after'] ) && ! hash_equals( $op['sha_after'], $actual ) && ! $force ) {
			return array( 'ok' => false, 'needs_force' => true, 'message' => __( 'This file changed after the fix. Restoring it would erase later work. Confirm the forced revert only if you are sure.', 'ai-bug-hunter' ) );
		}

		$written = ABH_Engine::write_file( $abs, $original, $rel );
		if ( empty( $written['ok'] ) ) {
			return array( 'ok' => false, 'message' => $written['message'] );
		}
		self::set_status( $op_id, 'rolled_back' );
		return array( 'ok' => true, 'message' => sprintf( /* translators: %s: reverted relative file path. */ __( 'Reverted: %s', 'ai-bug-hunter' ), $rel ) );
	}

	/**
	 * Revierte TODOS los archivos de una transacción multi-archivo.
	 *
	 * El journal guarda lo más reciente primero, que es exactamente el orden
	 * inverso de escritura: se restaura en ese orden para deshacer el conjunto
	 * de forma segura. Informa el resultado por archivo.
	 *
	 * @param string $txn_id Identificador de la transacción (TXN-…).
	 * @param bool   $force  Forzar aunque un archivo haya cambiado después.
	 * @return array
	 */
	public static function rollback_transaction( $txn_id, $force = false ) {
		$journal = self::journal();
		$ops     = array();
		$plan    = null;
		foreach ( $journal as $op ) {
			if ( ! isset( $op['txn_id'] ) || ! hash_equals( (string) $op['txn_id'], (string) $txn_id ) || 'rolled_back' === $op['status'] ) {
				continue;
			}
			// El plan de operaciones se anota como una sola fila y NO entra en
			// el lote: si entrara, revertirlo llamaría a rollback() con un
			// op_id que empieza por TXN- y volvería aquí para siempre.
			if ( isset( $op['action'] ) && 'plan' === $op['action'] ) {
				$plan = $op;
				continue;
			}
			$ops[] = $op;
		}

		// Plan de operaciones: sus copias para deshacer no viven en el almacén
		// de respaldos sino en el diario de la transacción, así que la
		// reversión la ejecuta quien las guardó. Sin esto el Historial
		// prometía una reversión que no tenía forma de cumplir.
		if ( null !== $plan && class_exists( 'ABH_Transaction' ) ) {
			$vuelta = ABH_Transaction::rollback( (string) $txn_id );
			if ( ! empty( $vuelta['ok'] ) ) {
				self::set_status( (string) $plan['op_id'], 'rolled_back' );
			}
			return $vuelta;
		}

		if ( empty( $ops ) ) {
			return array( 'ok' => false, 'message' => __( 'No pending operations were found for that transaction.', 'ai-bug-hunter' ) );
		}
		$mensajes = array();
		$fallos   = 0;
		foreach ( $ops as $op ) {
			$r = self::rollback( $op['op_id'], $force );
			if ( empty( $r['ok'] ) ) {
				$fallos++;
			}
			$mensajes[] = ( isset( $op['rel_path'] ) ? $op['rel_path'] : $op['op_id'] ) . ': ' . $r['message'];
		}
		if ( $fallos > 0 ) {
			return array(
				'ok'      => false,
				'partial' => count( $ops ) > $fallos,
				/* translators: 1: fallos, 2: total, 3: detalle. */
				'message' => sprintf( __( 'Incomplete revert (%1$d of %2$d failed). %3$s', 'ai-bug-hunter' ), $fallos, count( $ops ), implode( ' · ', $mensajes ) ),
			);
		}
		/* translators: 1: número de archivos, 2: detalle. */
		return array( 'ok' => true, 'message' => sprintf( __( 'Transaction reverted (%1$d files). %2$s', 'ai-bug-hunter' ), count( $ops ), implode( ' · ', $mensajes ) ) );
	}

	/**
	 * Borra únicamente las carpetas de respaldo conocidas.
	 *
	 * Su gemela cuidadosa es ABH_Health::prune(): aquélla se niega a barrer una
	 * transacción en curso o una reversión a medias porque sus copias son lo
	 * único que permite terminar de deshacerla. Ésta borraba exactamente eso
	 * —todos los archivos, las carpetas, el diario entero y la ruta guardada—
	 * sin mirar nada, con la misma capacidad, el mismo nonce y ni una
	 * confirmación de más. Un clic dejaba el sitio parcheado y sin marcha
	 * atrás, y ninguna pantalla lo contaba.
	 *
	 * Ahora las dos preguntan lo mismo, en el mismo sitio.
	 *
	 * @return array ok, message
	 */
	public static function purge() {
		if ( class_exists( 'ABH_Health' ) && ABH_Health::transaccion_en_vuelo() ) {
			return array(
				'ok'      => false,
				'message' => __( 'Nothing was deleted: a repair is being applied or a rollback was left half-finished, and these copies are the only thing that makes it possible to finish undoing it. Finish the revert from History and try again.', 'ai-bug-hunter' ),
			);
		}
		// El diario se borra con el mismo candado con el que se escribe: barrer
		// por debajo de una reparación que está anotando su fila deja el
		// respaldo en disco y la fila en ninguna parte.
		$testigo = self::journal_lock();
		if ( false === $testigo ) {
			return array( 'ok' => false, 'message' => self::journal_busy_message() );
		}

		foreach ( self::known_dirs() as $dir ) {
			// La raíz manda: si no resuelve a una carpeta propia —o si es, o
			// contiene, ABSPATH, wp-content o las subidas— no se abre siquiera.
			$raiz = self::safe_storage_root( $dir );
			if ( false === $raiz || ! is_dir( $raiz ) ) {
				continue;
			}
			$files = @scandir( $raiz );
			if ( is_array( $files ) ) {
				foreach ( $files as $name ) {
					if ( '.' === $name || '..' === $name ) {
						continue;
					}
					$file = $raiz . '/' . $name;
					if ( is_link( $file ) || ! is_file( $file ) || ! self::path_inside( $file, $raiz ) ) {
						continue;
					}
					if ( ! self::is_known_backup_path( $file ) ) {
						continue;
					}
					// El blindaje ya no se borra por su nombre, sino por ser el
					// que escribimos nosotros.
					if ( ! self::removable_name( $name ) && ! self::is_own_hardening_file( $file, $name ) ) {
						continue;
					}
					@unlink( $file );
				}
			}
			@rmdir( $raiz );
		}
		delete_option( self::OPTION_JOURNAL );
		delete_option( 'abh_backup_dir' );
		delete_transient( 'abh_journal_error' );
		self::$almacen_listo = false;
		self::journal_unlock( $testigo );
		return array( 'ok' => true, 'message' => __( 'Backups and history deleted.', 'ai-bug-hunter' ) );
	}
}
