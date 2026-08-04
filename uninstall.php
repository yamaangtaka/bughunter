<?php
/**
 * Desinstalación segura.
 *
 * Las claves de API y propuestas pendientes se eliminan SIEMPRE. El resto de
 * los ajustes, historial y respaldos solo se elimina cuando el administrador
 * activó la limpieza completa.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Borra datos del plugin, y con el borrado completo también las copias de seguridad.
 *
 * POR QUE EXISTE:  Un desinstalador que deja basura detrás es un desinstalador roto.
 *
 * SI LO RECORTAS:  AVISO: borrar las copias es IRREVERSIBLE. Si hay dos copias del plugin instaladas, comparten almacén y quitar una puede dejar a la otra sin sus respaldos.
 *
 * AI Bug Hunter es una herramienta de acceso tipo root al sitio, pensada
 * para superadministradores y agencias que entienden el riesgo. Lo que nos
 * protege no es quitarnos capacidades: es declararlas, avisar en todas las
 * pantallas y exigir confirmación escrita en lo grave.
 * ---------------------------------------------------------------------
 *
 * @package AI_Bug_Hunter
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- Uninstall removes only validated plugin-owned backup directories after the administrator enables full cleanup.

global $wpdb;

/**
 * LO QUE NO SE BORRA, Y POR QUÉ — lee esto antes de añadir una línea aquí.
 *
 * `abh_install` NO aparece en ninguna lista de borrado de este archivo, y su
 * ausencia es deliberada. Guarda el token de la instalación y el contador
 * monótono de las 3 reparaciones de por vida. Si se borrara, desinstalar y
 * volver a instalar sería un botón de reparaciones infinitas, y la promesa
 * «tres, no se renuevan» dejaría de significar nada.
 *
 * Es la única opción del plugin que sobrevive a propósito. Todo lo demás —
 * ajustes, historial, cachés, respaldos — se va según las reglas de abajo.
 */

$abh_settings = get_option( 'abh_settings', array() );
$abh_settings = is_array( $abh_settings ) ? $abh_settings : array();
$abh_wipe     = ! empty( $abh_settings['wipe_on_uninstall'] );

// Los secretos nunca sobreviven a la desinstalación.
unset( $abh_settings['api_key'], $abh_settings['api_key_enc'], $abh_settings['api_key_provider'], $abh_settings['api_key_binding'] );
if ( $abh_wipe ) {
	delete_option( 'abh_settings' );
} else {
	update_option( 'abh_settings', $abh_settings, false );
}

// Elimina todos los trabajos efímeros propios y sus timeouts sin conocer tokens.
if ( isset( $wpdb->options ) ) {
	$abh_transient_prefixes = array(
		'abh_pending_',
		'abh_thoth_',
		'abh_scan_',
		'abh_env_preview_',
		// Estos cuatro se quedaban atrás. Cada uno guarda sumas, huellas o
		// listados de archivos del sitio, y sobrevivían a la desinstalación
		// solo porque el barrido no conocía su prefijo.
		'abh_core_',
		'abh_src_',
		'abh_ai_ok_',
		'abh_deep_plugin_',
		// Cachés del servidor de autorización. Son caché, no identidad: lo que
		// tiene que sobrevivir es `abh_install`, y estos no.
		'abh_config_',
		'abh_authz_',
		'abh_register_',
		// Estado de redacción de la consola de chat (`abh_chat_priv_<32 hex>`).
		// No es basura corriente: guarda qué se ocultó y qué se dejó pasar en la
		// conversación, o sea privacidad del sitio. Quedarse detrás es lo peor
		// que puede hacer un dato así.
		'abh_chat_priv_',
		// Cerrojo y último error del diario de respaldos (`abh_journal_lock`,
		// `abh_journal_error`). El cerrojo sobreviviente deja el diario cerrado
		// por una transacción que ya no existe, y el error es un mensaje con
		// rutas del sitio. La opción `abh_journal` NO se toca aquí: este barrido
		// solo mira filas `_transient_…`, y esa se borra con la limpieza completa.
		'abh_journal_',
	);
	foreach ( $abh_transient_prefixes as $abh_prefix ) {
		$like_value = $wpdb->esc_like( '_transient_' . $abh_prefix ) . '%';
		$like_time  = $wpdb->esc_like( '_transient_timeout_' . $abh_prefix ) . '%';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like_value, $like_time ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall must remove transient rows directly; there is no cacheable read result.
	}

	// En multisitio los transients de red no viven en `options` sino en
	// `sitemeta`, con el prefijo `_site_transient_`. El barrido de arriba no los
	// veía, así que en una red quedaban filas nuestras detrás. Se limpian con
	// los mismos prefijos: si el objeto de caché externo se los quedó en RAM,
	// caducan solos; lo que no puede quedarse es la fila en la base de datos.
	if ( is_multisite() && isset( $wpdb->sitemeta ) ) {
		foreach ( $abh_transient_prefixes as $abh_prefix ) {
			$like_value = $wpdb->esc_like( '_site_transient_' . $abh_prefix ) . '%';
			$like_time  = $wpdb->esc_like( '_site_transient_timeout_' . $abh_prefix ) . '%';
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s", $like_value, $like_time ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall must remove network transient rows directly; there is no cacheable read result.
		}
	}
}

// El último reporte puede contener rutas y metadatos del sitio.
delete_option( 'abh_last_syntax_scan' );
delete_option( 'abh_plugin_scan_results' );
delete_option( 'abh_plugin_scan_history' );

// El testigo vive FUERA de la carpeta del plugin, así que borrar el plugin no
// lo retira: hay que hacerlo aquí o quedaría huérfano ejecutándose en cada
// petición del sitio para siempre. Se comprueba que sea nuestro antes de tocarlo.
$abh_wd_dir  = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
$abh_wd_file = rtrim( str_replace( '\\', '/', $abh_wd_dir ), '/' ) . '/abh-watchdog.php';
// Se aceptan las DOS marcas de cabecera: la actual, «AI Bug Hunter Witness», y
// la heredada en español, «AI Bug Hunter · Testigo». Los mu-plugins no admiten
// traducción por dominio de texto, así que la cabecera tuvo que reescribirse en
// inglés; pero el archivo que ya está en disco de una instalación anterior
// sigue llevando el literal viejo. Si dejásemos de reconocerlo, el testigo de
// esas instalaciones no se retiraría nunca y seguiría ejecutándose en cada
// petición del sitio con el plugin ya borrado. NO borres el literal heredado.
if ( file_exists( $abh_wd_file ) ) {
	$abh_wd_body = @file_get_contents( $abh_wd_file );
	if ( false !== $abh_wd_body
		&& false !== strpos( $abh_wd_body, 'ABH_WATCHDOG_OPTION' )
		&& ( false !== strpos( $abh_wd_body, 'AI Bug Hunter Witness' )
			|| false !== strpos( $abh_wd_body, 'AI Bug Hunter · Testigo' ) ) ) {
		if ( ! @unlink( $abh_wd_file ) ) {
			// Puede ser solo el bit de escritura de la carpeta. Se reintenta una
			// vez tras aflojar los permisos del archivo; si tampoco, se deja.
			@chmod( $abh_wd_file, 0644 );
			@unlink( $abh_wd_file );
		}
	}
}
delete_option( 'abh_watchdog_fatals' );

// Opciones de los subsistemas nuevos: no dejan datos del sitio detrás.
delete_option( 'abh_meter_ledger' );
delete_option( 'abh_cve_entries' );
delete_option( 'abh_cve_status' );
delete_option( 'abh_core_last_scan' );
delete_option( 'abh_core_accepted' );
// El cerrojo de aplicación es efímero por definición. Si sobrevive a una
// desinstalación, una reinstalación se encuentra la puerta cerrada por una
// transacción que ya no existe.
delete_option( 'abh_txn_lock' );
// Un armado de modo root que sobreviva a la desinstalación sería un permiso
// firmado para un plan que ya no existe.
delete_option( 'abh_root_armado' );
delete_option( 'abh_bienvenida_pendiente' );
delete_option( 'abh_primera_reparacion_hecha' );
// El diario de transacciones NO se deja atrás. Una reinstalación se
// encontraría asientos en «aplicando» o «revertida_parcial» que bloquean
// planes nuevos apuntando a copias que ya no existen.
delete_option( 'abh_txn_journal' );
delete_option( 'abh_version_vista' );
delete_option( 'abh_bienvenida_leida' );
// El último valor bueno de los parámetros comerciales es una caché con precios
// de ayer. No es identidad y no debe sobrevivir.
delete_option( 'abh_config_lkg' );
// El estado del aviso de soporte (ABH_Support::OPTION) no aparecía en ninguna
// lista y se quedaba en la tabla de opciones tras desinstalar.
delete_option( 'abh_support' );

// La marca por usuario de la consola de THOTH vivía en usermeta, y este archivo
// no tocaba usermeta en absoluto: quedaba una fila por cada administrador que
// hubiera abierto la consola alguna vez. El último parámetro en true hace que
// se borre para TODOS los usuarios en vez de para el id 0, que no existe.
delete_metadata( 'user', 0, 'abh_thoth_active', '', true );

// El cron diario del feed de vulnerabilidades solo se retiraba en el gancho de
// desactivación, y ABH_CVE::unschedule() quita una única marca de tiempo, no el
// gancho entero. Al desinstalar sin desactivar antes, WordPress se quedaba
// intentando ejecutar para siempre un gancho cuyo código ya no existe.
wp_clear_scheduled_hook( 'abh_cve_refresh' );

// En una red, ese gancho se programa en CADA sitio donde el plugin llegó a
// correr, porque el cron de WordPress es por sitio. La llamada de arriba solo
// limpia el sitio en el que WordPress ejecuta este desinstalador —y lo ejecuta
// UNA sola vez—, así que en todos los demás quedaba una entrada de cron
// apuntando a código ya borrado. El recorrido tiene que hacerlo este archivo.
// De paso se repite el barrido de transients, que también vive en la tabla de
// opciones de cada sitio: `switch_to_blog()` reapunta `$wpdb->options`.
if ( is_multisite() && function_exists( 'get_sites' ) && function_exists( 'switch_to_blog' ) ) {
	$abh_site_ids = get_sites(
		array(
			'fields'                 => 'ids',
			'number'                 => 0,
			'update_site_meta_cache' => false,
		)
	);
	if ( is_array( $abh_site_ids ) ) {
		foreach ( $abh_site_ids as $abh_site_id ) {
			switch_to_blog( (int) $abh_site_id );
			wp_clear_scheduled_hook( 'abh_cve_refresh' );
			// La lista se declara arriba dentro de su propia comprobación; si allí
			// no llegó a existir, aquí tampoco se usa.
			if ( isset( $wpdb->options ) && ! empty( $abh_transient_prefixes ) ) {
				foreach ( $abh_transient_prefixes as $abh_prefix ) {
					$like_value = $wpdb->esc_like( '_transient_' . $abh_prefix ) . '%';
					$like_time  = $wpdb->esc_like( '_transient_timeout_' . $abh_prefix ) . '%';
					$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like_value, $like_time ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall must remove transient rows directly on every site of the network; there is no cacheable read result.
				}
			}
			restore_current_blog();
		}
	}
}

/**
 * Utilidades de ruta. Se declaran aquí arriba porque el barrido de temporales
 * del registro las necesita ANTES del corte de la limpieza completa, y el
 * barrido del almacén las vuelve a usar más abajo. Son las mismas para todos:
 * una sola definición, un solo criterio.
 */
$abh_normalize = static function ( $path ) {
	return rtrim( str_replace( '\\', '/', (string) $path ), '/' );
};

/**
 * ¿Cuelga esta ruta de esa otra, comprobado con rutas ya resueltas?
 *
 * Ni la ruta ni la raíz pueden ser un enlace simbólico, y la contención se
 * decide sobre lo que devuelve realpath(): un enlace dentro del almacén que
 * apunte fuera no puede colar la carpeta de otro en un bucle de borrado.
 */
$abh_inside = static function ( $path, $root ) use ( $abh_normalize ) {
	$path = $abh_normalize( $path );
	$root = $abh_normalize( $root );
	if ( '' === $path || '' === $root || is_link( $path ) || is_link( $root ) ) {
		return false;
	}
	$path_real = realpath( $path );
	$root_real = realpath( $root );
	if ( false === $path_real || false === $root_real ) {
		return false;
	}
	$path_real = $abh_normalize( $path_real );
	$root_real = $abh_normalize( $root_real );
	return $path_real === $root_real || 0 === strpos( $path_real, $root_real . '/' );
};

// Borra un archivo y DICE si lo consiguió. Antes el resultado se tiraba, así
// que un fallo de permisos pasaba por limpieza correcta y encima se intentaba
// retirar una carpeta que seguía llena.
$abh_delete_file = static function ( $file ) {
	if ( @unlink( $file ) ) {
		return true;
	}
	// Casi siempre es solo el bit de escritura. Un reintento tras aflojarlo.
	@chmod( $file, 0644 );
	if ( @unlink( $file ) ) {
		return true;
	}
	clearstatcache( true, $file );
	return ! file_exists( $file );
};

/**
 * Temporales del limpiador del registro de errores.
 *
 * Ese limpiador reescribe el registro en un archivo temporal creado con
 * tempnam( $dir, 'abh-log-' ) DENTRO de la misma carpeta del registro, y lo
 * renombra encima al final. Si la petición se corta entre las dos cosas —un
 * timeout, un fatal, el navegador cerrado— el temporal se queda en disco con
 * parte del registro dentro. No es basura inocente: son líneas del log del
 * sitio, con rutas y trazas, en una carpeta que puede estar publicada.
 *
 * Se barren SIEMPRE, esté o no activada la limpieza completa: no son datos del
 * administrador que haya que conservar, son restos de una operación nuestra.
 *
 * Estas carpetas son del sitio, NO del plugin. Aquí solo se retiran archivos
 * sueltos cuyo nombre lleva nuestro prefijo exacto; no se borra ninguna otra
 * cosa y, sobre todo, no se retira ninguna carpeta.
 */
$abh_log_dirs  = array( WP_CONTENT_DIR, ABSPATH );
$abh_log_paths = array();
if ( defined( 'ABH_TRUSTED_LOG_PATH' ) && is_string( ABH_TRUSTED_LOG_PATH ) && '' !== trim( ABH_TRUSTED_LOG_PATH ) ) {
	$abh_log_paths[] = ABH_TRUSTED_LOG_PATH;
}
$abh_ini_log = ini_get( 'error_log' );
if ( is_string( $abh_ini_log ) && '' !== trim( $abh_ini_log ) && 'syslog' !== $abh_ini_log ) {
	$abh_log_paths[] = $abh_ini_log;
}
if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== trim( WP_DEBUG_LOG ) ) {
	$abh_log_paths[] = WP_DEBUG_LOG;
}
foreach ( $abh_log_paths as $abh_log_path ) {
	$abh_log_candidate = $abh_normalize( $abh_log_path );
	if ( false === strpos( $abh_log_candidate, '/' ) ) {
		// Ruta relativa: dirname() daría «.», o sea el directorio de trabajo
		// del proceso, que no tiene por qué ser nuestro. No se mira.
		continue;
	}
	$abh_log_dirs[] = dirname( $abh_log_candidate );
}
foreach ( array_unique( array_map( $abh_normalize, $abh_log_dirs ) ) as $abh_log_dir ) {
	if ( '' === $abh_log_dir || ! is_dir( $abh_log_dir ) || is_link( $abh_log_dir ) ) {
		continue;
	}
	$abh_log_names = @scandir( $abh_log_dir );
	if ( ! is_array( $abh_log_names ) ) {
		continue;
	}
	foreach ( $abh_log_names as $abh_log_name ) {
		// El nombre que deja tempnam(): nuestro prefijo literal más el sufijo
		// aleatorio que añade la propia función. Cualquier otra cosa no la
		// escribimos nosotros y se queda donde está.
		if ( ! preg_match( '/^abh-log-[A-Za-z0-9]{1,12}$/', (string) $abh_log_name ) ) {
			continue;
		}
		$abh_log_tmp = $abh_log_dir . '/' . $abh_log_name;
		// Mismo orden que en el barrido del almacén: primero se confirma que es
		// un archivo real y contenido en la carpeta, y solo entonces se borra.
		if ( ! is_file( $abh_log_tmp )
			|| is_link( $abh_log_tmp )
			|| ! $abh_inside( $abh_log_tmp, $abh_log_dir ) ) {
			continue;
		}
		if ( ! $abh_delete_file( $abh_log_tmp ) ) {
			// Resistió: sigue en disco con parte del registro dentro. Desde un
			// desinstalador no hay a quién avisar, pero el borrado tampoco se da
			// por hecho ni se compensa tocando nada más de una carpeta ajena.
			continue;
		}
		// Fuera. Se olvida lo que el caché de estado sepa de esa ruta.
		clearstatcache( true, $abh_log_tmp );
	}
}

if ( ! $abh_wipe ) {
	return;
}

$abh_key        = get_option( 'abh_storage_key', '' );
$abh_stored_dir = get_option( 'abh_backup_dir', '' );

foreach ( array(
	'abh_journal',
	'abh_dismissed',
	'abh_repaired',
	'abh_intact',
	'abh_storage_migrated',
	'abh_storage_migrated_v2',
	'abh_storage_key',
	'abh_backup_dir',
) as $abh_option ) {
	delete_option( $abh_option );
}

/**
 * Blindaje que este plugin escribe dentro de su carpeta privada.
 *
 * Copia literal de ABH_Backup::hardening_files(). El desinstalador se ejecuta
 * con el plugin ya descargado de memoria, así que no puede llamar a esa clase y
 * la tabla tiene que estar aquí. Si allí cambia el contenido, cambia también
 * aquí: lo que no coincida byte a byte deja de reconocerse como nuestro y se
 * queda en disco, que es el lado seguro del error.
 */
$abh_hardening = array(
	'.htaccess'  => "# BEGIN AI Bug Hunter\n"
		. "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
		. "<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n"
		. "Options -Indexes\n# END AI Bug Hunter\n",
	'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
	'index.php'  => "<?php\n// Silence is golden.\n",
);

/**
 * ¿Es este archivo de blindaje uno de los nuestros?
 *
 * Antes bastaba el NOMBRE: `.htaccess`, `web.config` e `index.php` se borraban
 * a ciegas en cualquier carpeta que llegara hasta este bucle. Con un almacén
 * apuntado a una carpeta compartida, eso se llevaba por delante el `.htaccess`
 * de otra aplicación y dejaba su contenido servido por la web. Ahora se compara
 * el CONTENIDO, exactamente igual que ABH_Backup::is_own_hardening_file().
 */
$abh_own_hardening = static function ( $file, $name ) use ( $abh_hardening ) {
	if ( ! isset( $abh_hardening[ $name ] ) ) {
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
	return hash_equals( $abh_hardening[ $name ], $actual );
};

// Nombres que son nuestros por su forma. El blindaje ya NO entra por aquí: lo
// decide $abh_own_hardening comparando el contenido.
$abh_removable = static function ( $name ) {
	if ( preg_match( '/^[a-f0-9]{12,64}__[^\/]+\.(?:abhbak|txt|bak|php|phtml)$/i', (string) $name ) ) {
		return true;
	}
	// Material descargado de WordPress.org y el índice derivado de él: el zip
	// del núcleo, los zips de plugins y temas, y el JSON «función => archivo».
	// Viven en `core-cache/`, un nivel por debajo del almacén, y el barrido solo
	// miraba el primer nivel: sobrevivían enteros a la desinstalación, con
	// decenas de megas de descargas y un listado de los archivos del sitio.
	return (bool) preg_match(
		'/^(?:wordpress-[0-9][0-9.]{0,15}-[A-Za-z0-9_]{2,12}\.zip'
		. '|(?:plugin|theme)-[A-Za-z0-9._-]{1,64}-[A-Za-z0-9._-]{1,32}\.zip'
		. '|functions-[0-9][0-9.]{0,15}-[A-Za-z0-9_]{2,12}\.json'
		// Copias de estudio del banco de pruebas, en `lab/`. Llevan dentro
		// código del sitio, así que tampoco pueden quedarse atrás.
		. '|[A-Za-z0-9]{8,64}\.lab)$/',
		(string) $name
	);
};

// Subcarpetas propias que se vacían antes de retirar el almacén. La lista es
// explícita a propósito: aquí no se recorre un árbol a ciegas, solo las dos
// carpetas que el plugin crea dentro del suyo.
$abh_subdirs = array( 'core-cache', 'lab' );

$abh_up   = wp_upload_dir();
$abh_dirs = array( trailingslashit( $abh_up['basedir'] ) . 'ai-bug-hunter-backups' );
if ( is_string( $abh_key ) && preg_match( '/^[A-Za-z0-9_-]{12,64}$/', $abh_key ) ) {
	$abh_dirs[] = trailingslashit( $abh_up['basedir'] ) . 'ai-bug-hunter-backups-' . $abh_key;
	$abh_dirs[] = dirname( rtrim( ABSPATH, '/\\' ) ) . '/.ai-bug-hunter-private-' . $abh_key;
	$abh_dirs[] = rtrim( WP_CONTENT_DIR, '/\\' ) . '/.ai-bug-hunter-private-' . $abh_key;
}
/**
 * ¿Es este el NOMBRE de una carpeta que crea este plugin?
 *
 * Son los únicos nombres que el plugin se pone a sí mismo: la carpeta privada
 * actual, `.ai-bug-hunter-private-<clave>`, y las dos heredadas bajo subidas.
 * Una carpeta que no se llame así no la creamos nosotros, por muy configurada
 * que esté.
 */
$abh_own_dir_name = static function ( $dir ) use ( $abh_normalize, $abh_key ) {
	$base = basename( $abh_normalize( $dir ) );
	if ( '' === $base ) {
		return false;
	}
	if ( 0 === strpos( $base, '.ai-bug-hunter-private-' ) ) {
		return true;
	}
	if ( 'ai-bug-hunter-backups' === $base ) {
		return true;
	}
	return is_string( $abh_key ) && '' !== $abh_key && 'ai-bug-hunter-backups-' . $abh_key === $base;
};

/**
 * ¿Lleva el nombre base el prefijo privado de este plugin?
 *
 * `.ai-bug-hunter-private-` es la marca que el plugin —y solo el plugin— se pone
 * a sí mismo al crear su almacén. Las dos rutas CONFIGURABLES, la constante
 * ABH_BACKUP_DIR y la opción `abh_backup_dir`, pasan por esta misma reja: son la
 * misma clase de dato, así que no pueden tener dos criterios distintos. Las
 * otras entradas de la lista no la necesitan porque no se leen de ninguna
 * configuración: se construyen aquí mismo, y por construcción son nuestras.
 */
$abh_private_prefix = static function ( $dir ) use ( $abh_normalize ) {
	$base = basename( $abh_normalize( $dir ) );
	return '' !== $base && 0 === strpos( $base, '.ai-bug-hunter-private-' );
};

/**
 * ABH_BACKUP_DIR entraba en la lista de borrado SIN comprobar nada, en contraste
 * con la ruta guardada de aquí abajo, que sí exige llamarse como nosotros.
 *
 * La constante la escribe a mano el dueño del servidor en wp-config.php y puede
 * apuntar a donde quiera, incluida una carpeta que comparte con otro contenido.
 * Ahí dentro el barrido encontraba `.htaccess`, `web.config` e `index.php` y —
 * cuando el borrable se decidía por el nombre— se los llevaba: una carpeta ajena
 * se quedaba sin su `.htaccess` y por tanto expuesta a la web. El contenido ya se
 * compara, pero la carpeta tampoco tiene por qué abrirse.
 *
 * Y no basta con que se llame como cualquiera de nuestras carpetas: se exige el
 * prefijo privado, exactamente el mismo que se le exige a la ruta guardada. Los
 * nombres heredados `ai-bug-hunter-backups[-<clave>]` valen para las rutas que
 * construimos nosotros bajo la carpeta de subidas, pero como nombre de una ruta
 * escrita a mano no prueban nada: cualquier carpeta puede llamarse así. Lo que
 * se pierde es que unos respaldos cifrados sobrevivan a la desinstalación en una
 * ruta que no lleva nuestra marca; lo que se gana es no borrar archivos de nadie
 * más. Ese es el lado seguro del error, y es el que se elige.
 *
 * No se le exige, en cambio, colgar de ABSPATH o de wp-content: sacar el almacén
 * fuera del sitio es justamente para lo que existe la constante.
 */
if ( defined( 'ABH_BACKUP_DIR' ) && is_string( ABH_BACKUP_DIR ) && '' !== trim( ABH_BACKUP_DIR ) && $abh_private_prefix( ABH_BACKUP_DIR ) ) {
	$abh_dirs[] = ABH_BACKUP_DIR;
}

// La ruta guardada se acepta solo si lleva el prefijo privado Y cuelga de donde
// el plugin crea su almacén. La constante, que existe justamente para sacarlo de
// ahí, no tiene esta segunda condición; el prefijo lo comparten las dos.
if ( is_string( $abh_stored_dir ) && '' !== $abh_stored_dir ) {
	$abh_ok = $abh_private_prefix( $abh_stored_dir )
		&& ( $abh_inside( $abh_stored_dir, dirname( rtrim( ABSPATH, '/\\' ) ) ) || $abh_inside( $abh_stored_dir, WP_CONTENT_DIR ) );
	if ( $abh_ok ) {
		$abh_dirs[] = $abh_stored_dir;
	}
}

/**
 * Raíces del sitio que NUNCA pueden ser el almacén del plugin.
 *
 * ABH_BACKUP_DIR la fija el dueño del servidor y `abh_backup_dir` es una opción
 * de la base de datos: cualquiera de las dos puede acabar apuntando, por un
 * error de configuración o por una fila manipulada, a la raíz de WordPress, a
 * wp-content o a la carpeta de subidas. Ahí dentro hay `.htaccess` e
 * `index.php` del propio sitio, y el barrido los borraba de la instalación viva
 * porque el blindaje entraba por su nombre. Ahora se compara el contenido y se
 * exige además que la carpeta se llame como nosotros, pero esta reja se queda:
 * si la ruta resuelve a una de estas carpetas —o por encima de ellas— no se
 * toca absolutamente nada, y ninguna de las tres comprobaciones depende de las
 * otras dos.
 */
$abh_forbidden_roots = array( ABSPATH, WP_CONTENT_DIR, $abh_up['basedir'] );

$abh_root_ok = static function ( $dir ) use ( $abh_normalize, $abh_forbidden_roots ) {
	$real = realpath( $dir );
	if ( false === $real ) {
		return false;
	}
	$real = $abh_normalize( $real );
	if ( '' === $real ) {
		return false;
	}
	foreach ( $abh_forbidden_roots as $abh_guard ) {
		$guard = realpath( $abh_guard );
		if ( false === $guard ) {
			continue;
		}
		$guard = $abh_normalize( $guard );
		if ( '' === $guard ) {
			continue;
		}
		// La propia carpeta protegida, o un ancestro suyo.
		if ( $real === $guard || 0 === strpos( $guard . '/', $real . '/' ) ) {
			return false;
		}
	}
	return true;
};

foreach ( array_unique( array_map( $abh_normalize, $abh_dirs ) ) as $abh_dir ) {
	if ( ! is_dir( $abh_dir ) || is_link( $abh_dir ) ) {
		continue;
	}
	if ( ! $abh_root_ok( $abh_dir ) ) {
		continue;
	}
	// Última reja, y a propósito redundante: toda entrada de la lista ya pasó su
	// propia comprobación de origen, pero una carpeta que no lleva uno de
	// nuestros nombres no se abre aquí pase lo que pase.
	if ( ! $abh_own_dir_name( $abh_dir ) ) {
		continue;
	}

	// Las subcarpetas primero: `rmdir` no vacía nada, y mientras `core-cache`
	// siguiera dentro el almacén no se podía retirar nunca.
	foreach ( $abh_subdirs as $abh_sub ) {
		$abh_sub_dir = $abh_dir . '/' . $abh_sub;
		// Cada NIVEL se comprueba entero, no solo la entrada del bucle: enlace
		// simbólico no, contención por realpath dentro del almacén sí, y la misma
		// reja de raíces protegidas que se le aplicó a la carpeta de arriba. Esa
		// última repetición no es adorno: si alguien apuntara la carpeta de
		// subidas —o wp-content— a `…/almacén/core-cache`, el nivel de entrada
		// seguiría pareciendo inocente y el barrido bajaría igual.
		if ( ! is_dir( $abh_sub_dir )
			|| is_link( $abh_sub_dir )
			|| ! $abh_inside( $abh_sub_dir, $abh_dir )
			|| ! $abh_root_ok( $abh_sub_dir ) ) {
			continue;
		}
		$abh_sub_left  = 0;
		$abh_sub_names = @scandir( $abh_sub_dir );
		if ( is_array( $abh_sub_names ) ) {
			foreach ( $abh_sub_names as $abh_name ) {
				if ( '.' === $abh_name || '..' === $abh_name ) {
					continue;
				}
				$abh_file = $abh_sub_dir . '/' . $abh_name;
				// El orden importa: primero se confirma que es un archivo real
				// dentro de la carpeta, y solo entonces se lee para compararlo.
				if ( ! is_file( $abh_file )
					|| is_link( $abh_file )
					|| ! $abh_inside( $abh_file, $abh_sub_dir )
					|| ( ! $abh_removable( $abh_name ) && ! $abh_own_hardening( $abh_file, $abh_name ) ) ) {
					++$abh_sub_left;
					continue;
				}
				if ( ! $abh_delete_file( $abh_file ) ) {
					++$abh_sub_left;
				}
			}
		} else {
			++$abh_sub_left;
		}
		if ( 0 === $abh_sub_left ) {
			clearstatcache( true, $abh_sub_dir );
			if ( ! @rmdir( $abh_sub_dir ) && is_dir( $abh_sub_dir ) ) {
				// Algunos sistemas de archivos en red siguen viendo la carpeta
				// ocupada justo después de vaciarla. Un segundo intento basta.
				clearstatcache( true, $abh_sub_dir );
				@rmdir( $abh_sub_dir );
			}
		}
	}

	$abh_left  = 0;
	$abh_files = @scandir( $abh_dir );
	if ( is_array( $abh_files ) ) {
		foreach ( $abh_files as $abh_name ) {
			if ( '.' === $abh_name || '..' === $abh_name ) {
				continue;
			}
			$abh_file = $abh_dir . '/' . $abh_name;
			// Mismo orden que arriba, y el blindaje solo cae si su contenido es
			// el que escribimos nosotros.
			if ( ! is_file( $abh_file )
				|| is_link( $abh_file )
				|| ! $abh_inside( $abh_file, $abh_dir )
				|| ( ! $abh_removable( $abh_name ) && ! $abh_own_hardening( $abh_file, $abh_name ) ) ) {
				++$abh_left;
				continue;
			}
			if ( ! $abh_delete_file( $abh_file ) ) {
				++$abh_left;
			}
		}
	} else {
		++$abh_left;
	}

	// La carpeta solo se retira si de verdad quedó vacía. El `rmdir` a ciegas
	// de antes fallaba en silencio y dejaba creer que se había limpiado.
	if ( 0 === $abh_left ) {
		clearstatcache( true, $abh_dir );
		if ( ! @rmdir( $abh_dir ) && is_dir( $abh_dir ) ) {
			clearstatcache( true, $abh_dir );
			@rmdir( $abh_dir );
		}
	}
}
