<?php
/**
 * Radio de daño: qué se rompe si este archivo se rompe.
 *
 * El dueño planteó una objeción seria a la contención: «la contención que impide
 * la corrección correcta nos mantendrá vulnerables por no poder conocer sus
 * debilidades». El diagnóstico es correcto. Prohibir tocar wp-config.php evita
 * el desastre, pero también impide aprender cómo sería el desastre, y algún día
 * le ocurrirá a un cliente sin que tengamos ni un dato.
 *
 * La respuesta NO es relajar la prohibición, y tampoco es ensayar el cambio
 * sobre una copia. Es dar el dato que faltaba sin tocar nada: decir con
 * exactitud qué cuesta un fallo en cada archivo, quién se queda fuera y desde
 * dónde se sale, antes de que nadie escriba una sola línea.
 *
 * Aquí solo se clasifica. No se lee el archivo, no se escribe nada y no se crea
 * ninguna carpeta: la respuesta se deduce de la ruta. Lo que devuelve informa;
 * no autoriza. Ningún resultado de este archivo habilita una escritura que los
 * límites prohíben.
 *
 * Por qué ya no hay banco de pruebas: hasta la tercera ronda vivía aquí un
 * ensayo que copiaba el archivo redactado a una carpeta .lab y aplicaba el
 * candidato SOBRE LA COPIA. Estaba mitigado y nunca tuvo un solo llamador en
 * esta edición, pero era el código que más cerca quedaba del límite: escribía
 * en disco contenido propuesto por un modelo. Se eliminó entero —el ensayo, la
 * carpeta aislada y su limpieza— para que ninguna edición futura lo encuentre
 * a mano. Una edición pública cuya promesa es «nunca aplica código generado
 * fuera» no debe cargar con la función que lo escribe.
 *
 * ---------------------------------------------------------------------
 * CAPACIDAD PELIGROSA - lee esto antes de «arreglar» este archivo.
 *
 * QUE PUEDE HACER: Ya nada peligroso: clasifica una ruta y devuelve texto. No lee archivos, no escribe en disco y no crea carpetas.
 *
 * POR QUE EXISTE:  Para que el usuario sepa qué cuesta exactamente un fallo en ese archivo antes de tocarlo.
 *
 * SI LO RECORTAS:  Sin este aviso se decide a ciegas sobre wp-config.php o .htaccess. Y no devuelvas aquí ninguna escritura: éste fue el archivo que más cerca estuvo del límite de la edición.
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
 * Class ABH_Lab
 */
class ABH_Lab {

	/**
	 * Radio de daño de un archivo: qué se rompe si este archivo se rompe.
	 *
	 * Determinista y sin modelo. Es la información que faltaba: no «está
	 * prohibido», sino «esto es exactamente lo que pasa».
	 *
	 * @param string $rel Ruta relativa.
	 * @return array scope, recoverable, consequence, recovery
	 */
	public static function blast_radius( $rel ) {
		$rel  = class_exists( 'ABH_Guard' ) ? ABH_Guard::normalize( $rel ) : (string) $rel;
		$base = strtolower( basename( str_replace( '\\', '/', (string) $rel ) ) );

		if ( 'wp-config.php' === $base ) {
			return array(
				'scope'       => __( 'Every request to the site, including the login screen.', 'ai-bug-hunter' ),
				'recoverable' => false,
				'consequence' => __( 'WordPress loads this file before anything else. A syntax error here blanks out the whole site and the dashboard as well: there is no screen left from which to undo it.', 'ai-bug-hunter' ),
				'recovery'    => __( 'Only through a file manager, FTP or SSH, restoring the file by hand. No plugin can help you, because no plugin even gets to load.', 'ai-bug-hunter' ),
			);
		}
		if ( '.htaccess' === $base ) {
			return array(
				'scope'       => __( 'Every request, at the web server level.', 'ai-bug-hunter' ),
				'recoverable' => false,
				'consequence' => __( 'Apache reads this file before running PHP. An invalid directive returns a 500 error across the whole site without PHP ever starting up, so as far as the server is concerned neither WordPress nor this plugin exist any more.', 'ai-bug-hunter' ),
				'recovery'    => __( 'Only through a file manager, FTP or SSH. This is the case where software can help the least.', 'ai-bug-hunter' ),
			);
		}
		if ( '.user.ini' === $base ) {
			return array(
				'scope'       => __( 'The PHP configuration for that folder and for the ones under it.', 'ai-bug-hunter' ),
				'recoverable' => false,
				'consequence' => __( 'Errors here are usually silent: PHP does not complain, it simply applies values different from the ones you think. A badly set limit can bring the site down intermittently and be very hard to trace.', 'ai-bug-hunter' ),
				'recovery'    => __( 'Through a file manager or FTP. PHP also caches this file for a few minutes, so the fix takes a while to show.', 'ai-bug-hunter' ),
			);
		}
		if ( in_array( $base, array( 'wp-settings.php', 'wp-load.php' ), true ) ) {
			return array(
				'scope'       => __( 'The startup of the WordPress core.', 'ai-bug-hunter' ),
				'recoverable' => false,
				'consequence' => __( 'It is part of the boot sequence. If it breaks, nothing starts, not even recovery mode.', 'ai-bug-hunter' ),
				'recovery'    => __( 'By restoring the original WordPress file over FTP, or by reinstalling core.', 'ai-bug-hunter' ),
			);
		}
		if ( false !== strpos( $rel, 'wp-content/mu-plugins/' ) ) {
			return array(
				'scope'       => __( 'Every request. mu-plugins cannot be deactivated.', 'ai-bug-hunter' ),
				'recoverable' => false,
				'consequence' => __( 'A mu-plugin always loads and does not show up in the plugin list with a deactivate button. If it fails, the whole site fails and there is no switch.', 'ai-bug-hunter' ),
				'recovery'    => __( 'By deleting or renaming the file over FTP or with a file manager.', 'ai-bug-hunter' ),
			);
		}
		if ( false !== strpos( $rel, 'wp-content/plugins/' ) ) {
			return array(
				'scope'       => __( 'The plugin it belongs to, and the pages where that plugin acts.', 'ai-bug-hunter' ),
				'recoverable' => true,
				'consequence' => __( 'WordPress detects the fatal error, deactivates that plugin and sends an email with a link to recovery mode. The rest of the site stays up.', 'ai-bug-hunter' ),
				'recovery'    => __( 'From the dashboard: recovery mode, or revert from this plugin\'s History, which stores the previous content encrypted.', 'ai-bug-hunter' ),
			);
		}
		if ( false !== strpos( $rel, 'wp-content/themes/' ) ) {
			return array(
				'scope'       => __( 'The visible part of the site.', 'ai-bug-hunter' ),
				'recoverable' => true,
				'consequence' => __( 'A broken theme takes down the front page, but WordPress can fall back to the default theme and the Dashboard is usually still reachable.', 'ai-bug-hunter' ),
				'recovery'    => __( 'By switching theme from the Dashboard, or by reverting from History.', 'ai-bug-hunter' ),
			);
		}
		return array(
			'scope'       => __( 'Scope not classified.', 'ai-bug-hunter' ),
			'recoverable' => true,
			'consequence' => __( 'There is no known rule for this file. Treat it as critical until you confirm otherwise.', 'ai-bug-hunter' ),
			'recovery'    => __( 'Revert from History if this plugin made the change; if not, from your backup.', 'ai-bug-hunter' ),
		);
	}
}
