<?php
/*
Plugin Name: Tolero blog spam filter
Plugin URI: http://tech.tolero.org/wordpress-blog-spam-filter-plugin/
Description: Tolero wordpress blog spam filter checks the submiter's bahavior. To operate properly it should have a physical access to the apache log file.
Version: 0.1
Author: Roman Balitsky
Author URI: http://tolero.org/
*/

class LogEntry {
	public $ip;
	public $date;
	public $file;
	public $agent;
}

/** This class in real is universal bot spam checker. It can be used to
 *  to protect any type of a messaging board (blog, forum, guest book, etc.)
 *  Currently supports only Apache powered boards, but this is because I do not
 *  have any other logs at hands. Just give me the log sample, and I'll add a
 *  support for it.
 *  Tolero.org bot check engine, version 0.1 */
class SpammerChecker {
	private $logFilePrimary;
	private $logFileSecondary;
	private $imagesRequired;
	private $logBlockSize = 1024;
	private $postFile     = "wp-comments-post.php";
	private $dateLast;
	private $dateChange   = 0;
	private $images       = Array();
	private $skipped      = 0;

	public function __construct($fileNamePrimary, $fileNameSecondary, $imagesRequired) {
		$this->logFilePrimary = $fileNamePrimary;
		$this->logFileSecondary = $fileNameSecondary;
		$this->imagesRequired = $imagesRequired;
	}
	
	public function isSpammer($userIp) {
		if (null !== $res = $this->processFile($this->logFilePrimary, $userIp)) {
			return $res;
		} elseif (!empty($this->logFileSecondary) && null !== $res = $this->processFile($this->logFileSecondary, $userIp)) {
			return $res;
		}
		return true;
	}

	private function processFile($fileName, $userIp) {
		$logSize   = filesize($fileName);
		$logHandle = fopen($fileName, 'r');

		$loop = true;

		while ($loop) {
			$logOffset = $this->logBlockSize * ++$iteraton;
			if ($logOffset < $logSize) {
				fseek($logHandle, $logSize - $logOffset, SEEK_SET);
				$logBlock = fread($logHandle, $this->logBlockSize);
				$entries = explode("\n", $logBlock);
				if (!empty($entries)) {
					array_push($entries, array_pop($entries) . $recordIncomplete);
					$recordIncomplete = array_shift($entries);
				} else {
					array_push($entries, $recordIncomplete);
				}
			} else {
				fseek($logHandle, 0);
				$logBlock = fread($logHandle, $logSize - $logOffset + $this->logBlockSize);
				$entries = explode("\n", $logBlock);
				if (!empty($entries)) {
					array_push($entries, array_pop($entries) . $recordIncomplete);
				} else {
					array_push($entries, $recordIncomplete);
				}
				$loop = false;
			}
			end($entries);
			while ($entry = current($entries)) {
				$res = $this->checkEntry($entry, $userIp);
				prev($entries);
				if (null !== $res) {
					fclose($logHandle);
					return $res;
				}
			}
		}
		fclose($logHandle);
		return null;
	}

	private function checkEntry($text, $userIp) {
		if ($this->doSkip($text, $userIp)) {
			return null;
		}
		$entry = $this->parseEntry($text);
		if ($this->checkDate($entry->date)) {
			return true;
		}
		if ($entry->ip != $userIp) {
			return null;
		}
		if ($this->isImage($entry->file) && !array_search($entry->file, $this->images)) {
			array_push($this->images, $entry->file);
			if ($this->imagesRequired == sizeof($this->images)) {
				return false;
			}
		}
		return null;
	}

	private function isImage($file) {
		return 1 == preg_match("/\\.(jpg|jpeg|gif|png|bmp)$/", $file);
	}

	private function checkDate($date) {
		if ($date != $this->dateLast) {
			$this->dateLast = $date;
			if (3 == ++$this->dateChange) {
				return true;
			}
		}
	}

	private function parseEntry($text) {
		preg_match('/^([^ ]*).*\\[(\\d{2}\\/\\S{3}\\/\\d{4}).*(?:GET|POST) ([^ ]*).*"(.*?)"$/', $text, $match);
		array_shift($match);
		$entry = new LogEntry();
		list($entry->ip, $entry->date, $entry->file, $entry->agent) = $match;
		return $entry;
	}

	private function doSkip($text, $userIp) {
		if (0 != strncmp($text, $userIp . " ", strlen($userIp) + 1) && 100 > $this->skipped) {
			++$this->skipped;
			return true;
		}
		$this->skipped = 0;
		return false;
	}
}

function tolero_filter_init() {
	global $tolero_filter_images_count, $tolero_filter_server_log_file_pri, $tolero_filter_server_log_file_sec;
	add_action('admin_menu', 'tolero_filter_config_page');
	if (false === $tolero_filter_images_count = get_option('tolero_filter_images_count')) {
		$tolero_filter_images_count = 2;
		update_option('tolero_filter_images_count', $tolero_filter_images_count);
	}
	if (false === $tolero_filter_server_log_file_pri = get_option('tolero_filter_server_log_file_pri')) {
		$tolero_filter_server_log_file_pri = "/var/log/apache2/access.log";
		update_option('tolero_filter_server_log_file_pri', $tolero_filter_server_log_file_pri);
	}
	if (false === $tolero_filter_server_log_file_sec = get_option('tolero_filter_server_log_file_sec')) {
		$tolero_filter_server_log_file_sec = "/var/log/apache2/access.log.1";
		update_option('tolero_filter_server_log_file_sec', $tolero_filter_server_log_file_sec);
	}
}

add_action('init', 'tolero_filter_init');

function tolero_filter_config_page() {
	if ( function_exists('add_submenu_page') )
		add_submenu_page('plugins.php', __('Tolero filter Configuration'), __('Tolero filter Configuration'), 'manage_options', 'tolero-filter-config', 'tolero_filter_conf');
}

function tolero_filter_conf() {
	global $tolero_filter_images_count, $tolero_filter_server_log_file_pri, $tolero_filter_server_log_file_sec;
	if (!empty($_POST)) {
		if (isset($_POST['images_count'])) {
			$tolero_filter_images_count = trim($_POST['images_count']);
			update_option('tolero_filter_images_count', $tolero_filter_images_count);
		}
		if (isset($_POST['server_log_file_pri'])) {
			$tolero_filter_server_log_file_pri = trim($_POST['server_log_file_pri']);
			update_option('tolero_filter_server_log_file_pri', $tolero_filter_server_log_file_pri);
		}
		if (isset($_POST['server_log_file_sec'])) {
			$tolero_filter_server_log_file_sec = trim($_POST['server_log_file_sec']);
			update_option('tolero_filter_server_log_file_sec', $tolero_filter_server_log_file_sec);
		}
		?><div id="message-saved" class="updated fade"><p><strong><?php _e('Configuration saved.') ?></strong></p></div><?php
	}
	if (!is_numeric($tolero_filter_images_count) || 1 > $tolero_filter_images_count || 65535 < $tolero_filter_images_count) {
		?><div id="message-image-invalid" class="updated fade-ff0000"><p><strong><?php _e('Images count value is invalid.') ?></strong></p></div><?php
	}
	if (true !== tolero_filter_check_log_file($tolero_filter_server_log_file_pri)) {
		?><div id="message-log-file-pri-invalid" class="updated fade-ff0000"><p><strong><?php _e("Unable to open primary log file for reading. Check the file path and the access permissions") ?></strong></p></div><?php
	}
	if (false === tolero_filter_check_log_file($tolero_filter_server_log_file_sec)) {
		?><div id="message-log-file-sec-invalid" class="updated fade-ff0000"><p><strong><?php _e("Unable to open secondary log file for reading. Check the file path and the access permissions") ?></strong></p></div><?php
	} ?>
	<div class="wrap">
	<h2><?php _e('Tolero filter Configuration'); ?></h2>
	<form action="" method="post" id="tolero-filter-conf">
	<p class="submit"><input type="submit" name="Submit" value="<?php _e('Update Config &raquo;') ?>" /></p>
	<table class="optiontable"> 
	<tr valign="top"> 
	<th scope="row"><?php _e('Images count:') ?></th> 
	<td><input name="images_count" type="text" id="images_count" value="<?php echo $tolero_filter_images_count; ?>" size="5" maxlength="5"/> <?php _e('<em>Default: 2</em>'); ?>
	<br />
	<?php _e('Minimal amount of image files to be get from page by submitter. Most spam bots doesn\'t process imagess at all, some of them rarely get one. The default wordpress design contains a 4 images, so feel free to setup 2 there if you\'re on it.') ?></td> 
	</tr> 
	<tr valign="top"> 
	<th scope="row"><?php _e('Apache log file (primary):') ?></th> 
	<td><input name="server_log_file_pri" type="text" id="server_log_file_pri" value="<?php echo $tolero_filter_server_log_file_pri; ?>" size="95%" />
	<br />
	<?php _e('Provide here full path and the name of the primary log file. It should be in a default apache format.') ?></td> 
	</tr> 
	<tr valign="top"> 
	<th scope="row"><?php _e('Apache log file (secondary):') ?></th> 
	<td><input name="server_log_file_sec" type="text" id="server_log_file_sec" value="<?php echo $tolero_filter_server_log_file_sec; ?>" size="95%" />
	<br />
	<?php _e('If you\'re using a logrotate, provide here a full path to the secondary log file, or leave it blank if not. Summary data of your both log files should always contain at least a two days data.') ?></td> 
	</tr> 
	</table> 
	<?php wp_nonce_field('update-tolero-filter-config'); ?>
	</form>
	</div>
	<?php
}

function tolero_filter_check_log_file($file) {
	return empty($file) ? null : (($f = @fopen($file, "r")) && @fclose($f));
}

function tolero_filter_check_comment($comment) {
	$ip = preg_replace('/[^0-9., ]/', '', $_SERVER['REMOTE_ADDR']);
	global $tolero_filter_images_count, $tolero_filter_server_log_file_pri, $tolero_filter_server_log_file_sec;
	$sc = new SpammerChecker($tolero_filter_server_log_file_pri, $tolero_filter_server_log_file_sec, $tolero_filter_images_count);
	if ($sc->isSpammer($ip)) {
		add_filter('pre_comment_approved', create_function('$a', 'return \'spam\';'));
	}
	return $comment;
}

add_action('preprocess_comment', 'tolero_filter_check_comment', 1);

function tolero_filter_spam_count() {
	global $wpdb;
	$count = $wpdb->get_var("SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved = 'spam'");
	return $count;
}

?>
