<?php
ob_start(); // Catch stray output that would break JSON
// admin.php — Scicel Media Backend v8 (stable)
define('APP_VERSION','9.1.0');
define('UPDATE_URL','https://raw.githubusercontent.com/LimitGames2121/link-in-bio/main/'); // ← GitHub Username eintragen!
define('DB_HOST','DEIN-DB-HOST.your-database.de');
define('DB_NAME','DEIN_DATENBANKNAME');
define('DB_USER','DEIN_DB_BENUTZER');
define('DB_PASS','DEIN_DB_PASSWORT');

header('Content-Type: application/json; charset=UTF-8');
$o=$_SERVER['HTTP_ORIGIN']??'';$h=$_SERVER['HTTP_HOST']??'';
if($o&&strpos($o,$h)!==false){header('Access-Control-Allow-Origin: '.$o);header('Access-Control-Allow-Credentials: true');}
header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://api.qrserver.com https://cdn.simpleicons.org blob:; connect-src 'self' https://ipapi.co https://accounts.spotify.com https://api.spotify.com; frame-src https://www.youtube.com https://player.twitch.tv; media-src 'self' blob:;");

ob_start(); // Buffer all output - prevents any PHP warnings from breaking JSON
session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();
// DON'T regenerate on every request - breaks session data including rate limiter

$isUp=!empty($_FILES);
if(!$isUp){
  if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['ok'=>false,'msg'=>'Method not allowed']);exit;}
  $body=json_decode(file_get_contents('php://input'),true)??[];
  $action=$body['action']??'';
}else{$action=$_POST['action']??'upload_image';}

// ── Helpers ────────────────────────────────────────────
function rl($a,$mx=20){$ip=hash('sha256',($_SERVER['REMOTE_ADDR']??'').'rl_v3');$k="rl_{$ip}_{$a}";if(!isset($_SESSION[$k]))$_SESSION[$k]=['c'=>0,'r'=>time()+60];if(time()>$_SESSION[$k]['r'])$_SESSION[$k]=['c'=>0,'r'=>time()+60];$_SESSION[$k]['c']++;return$_SESSION[$k]['c']<=$mx;}
function getDB(){static $p=null;if($p)return $p;try{$p=new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',DB_USER,DB_PASS,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);}catch(PDOException $e){http_response_code(500);echo json_encode(['ok'=>false,'msg'=>'DB Fehler: '.$e->getMessage()]);exit;}return $p;}
function hashIp($ip){return hash('sha256',$ip.'scicel_v8');}
function sessOk(){if(empty($_SESSION['auth']))return false;if($_SESSION['exp']<time()){session_destroy();return false;}$_SESSION['exp']=time()+1800;return true;}
function getLock(){return getDB()->query("SELECT * FROM lockout LIMIT 1")->fetch()?:['attempts'=>0,'until'=>0];}
function setLock($n,$u){getDB()->prepare("UPDATE lockout SET attempts=?,until=?")->execute([$n,$u]);}
function isLocked(){$l=getLock();$now=round(microtime(true)*1000);if($l['until']>$now)return true;if($l['until']>0&&$l['until']<=$now)setLock(0,0);return false;}

function logActivity($action,$detail=''){
  $ip=hashIp($_SERVER['REMOTE_ADDR']??'');
  try{getDB()->prepare("INSERT INTO activity_log(action,detail,ip_hash)VALUES(?,?,?)")->execute([$action,substr($detail,0,500),$ip]);
  getDB()->exec("DELETE FROM activity_log WHERE id NOT IN(SELECT id FROM(SELECT id FROM activity_log ORDER BY id DESC LIMIT 200)t)");}
  catch(Exception $e){}
}
function logLogin($ok,$r=''){
  try{$ip=hashIp($_SERVER['REMOTE_ADDR']??'');$ua=substr($_SERVER['HTTP_USER_AGENT']??'',0,300);
  getDB()->prepare("INSERT INTO login_log(ip_hash,user_agent,success,reason)VALUES(?,?,?,?)")->execute([$ip,$ua,$ok?1:0,$r]);
  getDB()->exec("DELETE FROM login_log WHERE id NOT IN(SELECT id FROM(SELECT id FROM login_log ORDER BY id DESC LIMIT 100)t)");}
  catch(Exception $e){}
}
function genCsrf(){if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(32));return $_SESSION['csrf'];}
function verifyCsrf($t){
  if(empty($_SESSION['csrf'])||empty($t)||!hash_equals($_SESSION['csrf'],$t??'')){
    logActivity('csrf_fail','Token mismatch - blocked');
    http_response_code(403);
    echo json_encode(['ok'=>false,'msg'=>'Ungültige Anfrage. Bitte Seite neu laden.']);
    exit;
  }
  // Rotate CSRF token after use for extra security
  $_SESSION['csrf']=bin2hex(random_bytes(32));
}
function isBlacklisted(){
  try{$ip=hashIp($_SERVER['REMOTE_ADDR']??'');$r=getDB()->prepare("SELECT id FROM ip_blacklist WHERE ip_hash=?");$r->execute([$ip]);return (bool)$r->fetch();}
  catch(Exception $e){return false;}
}

// ── TOTP ───────────────────────────────────────────────
function b32d($s){$s=strtoupper(preg_replace('/[^A-Z2-7]/','', $s));$m=array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));$b='';foreach(str_split($s)as $c){if(isset($m[$c]))$b.=str_pad(decbin($m[$c]),5,'0',STR_PAD_LEFT);}$r='';foreach(str_split($b,8)as $ch){if(strlen($ch)===8)$r.=chr(bindec($ch));}return $r;}
function genTotp($s,$ts=null){$k=b32d($s);if(!$k)return false;$t=$ts??floor(time()/30);$msg=pack('N*',0).pack('N*',$t);$h=hash_hmac('sha1',$msg,$k,true);$off=ord($h[19])&0xf;$c=((ord($h[$off])&0x7f)<<24)|((ord($h[$off+1])&0xff)<<16)|((ord($h[$off+2])&0xff)<<8)|(ord($h[$off+3])&0xff);return str_pad($c%1000000,6,'0',STR_PAD_LEFT);}
function verTotp($s,$c){$t=floor(time()/30);for($i=-1;$i<=1;$i++){if(genTotp($s,$t+$i)===$c)return true;}return false;}
function newSecret(){$c='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$s='';for($i=0;$i<32;$i++)$s.=$c[random_int(0,31)];return $s;}
function totpUri($s){return 'otpauth://totp/'.urlencode('Scicel Media').':Admin?secret='.$s.'&issuer='.urlencode('Scicel Media').'&algorithm=SHA1&digits=6&period=30';}

// ── DB Setup ───────────────────────────────────────────
function setupDB(){
  $db=getDB();
  // Core tables
  $db->exec("CREATE TABLE IF NOT EXISTS admin(id INT AUTO_INCREMENT PRIMARY KEY,pw_hash VARCHAR(255) NOT NULL,totp_secret VARCHAR(64) DEFAULT NULL,totp_enabled TINYINT DEFAULT 0,created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  $db->exec("CREATE TABLE IF NOT EXISTS lockout(id INT AUTO_INCREMENT PRIMARY KEY,attempts INT DEFAULT 0,until BIGINT DEFAULT 0)");
  $db->exec("CREATE TABLE IF NOT EXISTS login_log(id INT AUTO_INCREMENT PRIMARY KEY,ip_hash VARCHAR(64),user_agent VARCHAR(300),success TINYINT DEFAULT 0,reason VARCHAR(100),created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  $db->exec("CREATE TABLE IF NOT EXISTS activity_log(id INT AUTO_INCREMENT PRIMARY KEY,action VARCHAR(100),detail TEXT,ip_hash VARCHAR(64),created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  $db->exec("CREATE TABLE IF NOT EXISTS link_clicks(id INT AUTO_INCREMENT PRIMARY KEY,link_label VARCHAR(255),link_url VARCHAR(500),clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,ip_hash VARCHAR(64))");
  $db->exec("CREATE TABLE IF NOT EXISTS visitor_stats(id INT AUTO_INCREMENT PRIMARY KEY,visit_date DATE NOT NULL,count INT DEFAULT 0,UNIQUE KEY date_unique(visit_date))");
  $db->exec("CREATE TABLE IF NOT EXISTS utm_stats(id INT AUTO_INCREMENT PRIMARY KEY,visit_date DATE NOT NULL,source VARCHAR(100),medium VARCHAR(100),campaign VARCHAR(100),referrer VARCHAR(200),count INT DEFAULT 1,UNIQUE KEY utm_u(visit_date,source,medium,campaign))");
  $db->exec("CREATE TABLE IF NOT EXISTS ab_clicks(id INT AUTO_INCREMENT PRIMARY KEY,slug VARCHAR(100),label VARCHAR(255),variant CHAR(1),url VARCHAR(500),ip_hash VARCHAR(64),clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  $db->exec("CREATE TABLE IF NOT EXISTS live_visitors(id INT AUTO_INCREMENT PRIMARY KEY,slug VARCHAR(100),ip_hash VARCHAR(64),last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,UNIQUE KEY live_u(slug,ip_hash))");
  $db->exec("CREATE TABLE IF NOT EXISTS link_reactions(id INT AUTO_INCREMENT PRIMARY KEY,slug VARCHAR(100),link_label VARCHAR(255),reaction VARCHAR(20),ip_hash VARCHAR(64),created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE KEY react_u(slug,link_label,reaction,ip_hash))");
  $db->exec("CREATE TABLE IF NOT EXISTS device_stats(id INT AUTO_INCREMENT PRIMARY KEY,visit_date DATE NOT NULL,device_type VARCHAR(20),hour TINYINT,country VARCHAR(10) DEFAULT '',count INT DEFAULT 1,UNIQUE KEY dev_u(visit_date,device_type,hour,country))");
  $db->exec("CREATE TABLE IF NOT EXISTS pw_reset(id INT AUTO_INCREMENT PRIMARY KEY,token VARCHAR(64) UNIQUE,expires BIGINT,used TINYINT DEFAULT 0,created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  $db->exec("CREATE TABLE IF NOT EXISTS ip_blacklist(id INT AUTO_INCREMENT PRIMARY KEY,ip_hash VARCHAR(64) UNIQUE,reason VARCHAR(200),created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  // Profiles table
  $db->exec("CREATE TABLE IF NOT EXISTS profiles(
    id INT AUTO_INCREMENT PRIMARY KEY,slug VARCHAR(100) NOT NULL UNIQUE,name VARCHAR(255) NOT NULL DEFAULT '',
    bio TEXT,emoji VARCHAR(20) DEFAULT '🎬',logo_url VARCHAR(500) DEFAULT '',
    avatar_url VARCHAR(500) DEFAULT '',avatar_animated TINYINT DEFAULT 0,favicon_url VARCHAR(500) DEFAULT '',
    color1 VARCHAR(20) DEFAULT '#00e5ff',color2 VARCHAR(20) DEFAULT '#7b5cff',font_family VARCHAR(100) DEFAULT 'DM Sans',
    bg_image VARCHAR(500) DEFAULT '',bg_particles TINYINT DEFAULT 0,particle_style VARCHAR(20) DEFAULT 'stars',
    name_animated TINYINT DEFAULT 0,og_title VARCHAR(255) DEFAULT '',og_desc TEXT,
    page_title VARCHAR(255) DEFAULT '',footer_text VARCHAR(500) DEFAULT 'Made with Scicel Media',
    footer_visible TINYINT DEFAULT 1,ambient_sound VARCHAR(500) DEFAULT '',lang_enabled TINYINT DEFAULT 0,
    announce_enabled TINYINT DEFAULT 0,announce_text VARCHAR(500) DEFAULT '',announce_style VARCHAR(20) DEFAULT 'accent',
    twitch_enabled TINYINT DEFAULT 0,twitch_username VARCHAR(100) DEFAULT '',twitch_client_id VARCHAR(200) DEFAULT '',twitch_client_secret VARCHAR(200) DEFAULT '',milestone_enabled TINYINT DEFAULT 0,milestone_title VARCHAR(200) DEFAULT '',milestone_current INT DEFAULT 0,milestone_target INT DEFAULT 1000,milestone_unit VARCHAR(50) DEFAULT 'Member',    spotify_enabled TINYINT DEFAULT 0,spotify_client_id VARCHAR(200) DEFAULT '',
    spotify_client_secret VARCHAR(200) DEFAULT '',spotify_refresh_token VARCHAR(500) DEFAULT '',
    imp_name VARCHAR(200) DEFAULT '',imp_address VARCHAR(300) DEFAULT '',imp_email VARCHAR(200) DEFAULT '',
    imp_phone VARCHAR(50) DEFAULT '',imp_vat VARCHAR(50) DEFAULT '',imp_extra TEXT,
    webhook_enabled TINYINT DEFAULT 0,webhook_url VARCHAR(500) DEFAULT '',
    avatar_filter VARCHAR(30) DEFAULT 'filter-none',
    links LONGTEXT,maint TINYINT DEFAULT 0,maint_text TEXT,
    cookie_banner TINYINT DEFAULT 1,cookie_text TEXT,created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )");
  // Seed data
  if($db->query("SELECT COUNT(*) FROM admin")->fetchColumn()==0)
    $db->prepare("INSERT INTO admin(pw_hash)VALUES(?)")->execute([password_hash('template2024',PASSWORD_BCRYPT,['cost'=>12])]);
  if($db->query("SELECT COUNT(*) FROM lockout")->fetchColumn()==0)
    $db->exec("INSERT INTO lockout(attempts,until)VALUES(0,0)");
  if($db->query("SELECT COUNT(*) FROM profiles")->fetchColumn()==0){
    $dl=json_encode([
      ['emoji'=>'📺','label'=>'Twitch','label_en'=>'Twitch','url'=>'https://twitch.tv/scicel','color'=>'#9146ff','protected'=>false,'expires'=>'','starts'=>'','badge'=>'live','video'=>'','thumb'=>'','countdown'=>'','ab_variant'=>'','ab_label'=>'','geo_block'=>'','reactions_enabled'=>true],
      ['emoji'=>'💬','label'=>'Discord Server','label_en'=>'Discord Server','url'=>'https://discord.gg/scicel','color'=>'#5865f2','protected'=>false,'expires'=>'','starts'=>'','badge'=>'','video'=>'','thumb'=>'','countdown'=>'','ab_variant'=>'','ab_label'=>'','geo_block'=>'','reactions_enabled'=>true],
      ['emoji'=>'📸','label'=>'Instagram','label_en'=>'Instagram','url'=>'https://instagram.com/scicel','color'=>'linear-gradient(135deg,#833ab4,#fd1d1d,#fcb045)','protected'=>false,'expires'=>'','starts'=>'','badge'=>'neu','video'=>'','thumb'=>'','countdown'=>'','ab_variant'=>'','ab_label'=>'','geo_block'=>'','reactions_enabled'=>true],
      ['emoji'=>'🎵','label'=>'TikTok','label_en'=>'TikTok','url'=>'https://tiktok.com/@scicel','color'=>'#010101','protected'=>false,'expires'=>'','starts'=>'','badge'=>'','video'=>'','thumb'=>'','countdown'=>'','ab_variant'=>'','ab_label'=>'','geo_block'=>'','reactions_enabled'=>true],
      ['emoji'=>'▶️','label'=>'YouTube','label_en'=>'YouTube','url'=>'https://youtube.com/@scicel','color'=>'#ff0000','protected'=>false,'expires'=>'','starts'=>'','badge'=>'hot','video'=>'','thumb'=>'','countdown'=>'','ab_variant'=>'','ab_label'=>'','geo_block'=>'','reactions_enabled'=>true],
    ],JSON_UNESCAPED_UNICODE);
    $db->prepare("INSERT INTO profiles(slug,name,bio,emoji,links,maint_text,cookie_text,footer_text)VALUES(?,?,?,?,?,?,?,?)")
      ->execute(['main','Scicel Media','Kreativstudio · Content · Medienproduktion 🎥','🎬',$dl,'Wir arbeiten gerade an Verbesserungen. Bald sind wir zurück!','Diese Seite verwendet keine Tracking-Cookies.','Made with Scicel Media']);
  }
  // Safe ALTER TABLE — add missing columns to existing DBs
  $alterCols=[
    'lang_enabled TINYINT DEFAULT 0','announce_enabled TINYINT DEFAULT 0',
    'announce_text VARCHAR(500) DEFAULT ""','announce_style VARCHAR(20) DEFAULT "accent"',
    'spotify_enabled TINYINT DEFAULT 0','spotify_client_id VARCHAR(200) DEFAULT ""',
    'spotify_client_secret VARCHAR(200) DEFAULT ""','spotify_refresh_token VARCHAR(500) DEFAULT ""',
    'imp_name VARCHAR(200) DEFAULT ""','imp_address VARCHAR(300) DEFAULT ""',
    'imp_email VARCHAR(200) DEFAULT ""','imp_phone VARCHAR(50) DEFAULT ""',
    'imp_vat VARCHAR(50) DEFAULT ""','imp_extra TEXT',
    'twitch_enabled TINYINT DEFAULT 0','twitch_username VARCHAR(100) DEFAULT ""','twitch_client_id VARCHAR(200) DEFAULT ""','twitch_client_secret VARCHAR(200) DEFAULT ""','milestone_enabled TINYINT DEFAULT 0','milestone_title VARCHAR(200) DEFAULT ""','milestone_current INT DEFAULT 0','milestone_target INT DEFAULT 1000','milestone_unit VARCHAR(50) DEFAULT "Member"',    'webhook_enabled TINYINT DEFAULT 0','webhook_url VARCHAR(500) DEFAULT ""',
    'avatar_filter VARCHAR(30) DEFAULT "filter-none"',
  ];
  // Whitelist validation: $col comes from hardcoded array above - no user input
  // Extra safety: only allow valid SQL column definitions
  foreach($alterCols as $col){
    if(!preg_match('/^[a-z_]+ (?:VARCHAR|TEXT|TINYINT|INT|BIGINT|TIMESTAMP)(?:\([0-9,]+\))?(?: DEFAULT (?:"[^"]*"|[0-9]+|NULL))?$/i',$col)){
      error_log('Invalid alter col rejected: '.$col);continue;
    }
    try{$db->exec("ALTER TABLE profiles ADD COLUMN $col");}catch(Exception $e){}
  }
  try{$db->exec("ALTER TABLE admin ADD COLUMN totp_secret VARCHAR(64) DEFAULT NULL");}catch(Exception $e){}
  try{$db->exec("ALTER TABLE admin ADD COLUMN totp_enabled TINYINT DEFAULT 0");}catch(Exception $e){}
}

function getProfile($slug){
  $db=getDB();$s=$db->prepare("SELECT * FROM profiles WHERE slug=?");$s->execute([$slug]);$p=$s->fetch();if(!$p)return null;
  $p['links']=json_decode($p['links']??'[]',true)??[];
  $now=date('Y-m-d');
  $p['links']=array_values(array_filter($p['links'],fn($l)=>(empty($l['expires'])||$l['expires']>=$now)&&(empty($l['starts'])||$l['starts']<=$now)));
  return $p;
}
function saveProfile($slug,$data){
  $db=getDB();$lj=json_encode($data['links']??[],JSON_UNESCAPED_UNICODE);
  $f=['name','bio','emoji','logo_url','avatar_url','avatar_animated','favicon_url','color1','color2','font_family',
      'bg_image','bg_particles','particle_style','name_animated','og_title','og_desc','page_title','footer_text',
      'footer_visible','ambient_sound','lang_enabled','announce_enabled','announce_text','announce_style',
      'spotify_enabled','spotify_client_id','spotify_client_secret','spotify_refresh_token',
      'twitch_enabled','twitch_username','twitch_client_id','twitch_client_secret','milestone_enabled','milestone_title','milestone_current','milestone_target','milestone_unit','imp_name','imp_address','imp_email','imp_phone','imp_vat','imp_extra',
      'webhook_enabled','webhook_url','avatar_filter',
      'maint','maint_text','cookie_banner','cookie_text'];
  $sets=implode(',',array_map(fn($x)=>"`$x`=?",$f));
  $vals=array_map(fn($x)=>$data[$x]??null,$f);$vals[]=$lj;$vals[]=$slug;
  $db->prepare("UPDATE profiles SET $sets,links=? WHERE slug=?")->execute($vals);
}

try{setupDB();}catch(Exception $e){error_log('setupDB: '.$e->getMessage());}

// ── Router ─────────────────────────────────────────────
switch($action){
case 'get_csrf': echo json_encode(['ok'=>true,'token'=>genCsrf()]);break;

case 'login':
  if(!empty($body['website'])){logLogin(false,'honeypot');echo json_encode(['ok'=>false,'msg'=>'Fehler.']);exit;}
  if(isBlacklisted()){logLogin(false,'blacklisted');echo json_encode(['ok'=>false,'msg'=>'Zugriff verweigert.']);exit;}
  if(!rl('login',10)){logLogin(false,'rate_limit');echo json_encode(['ok'=>false,'msg'=>'Zu viele Anfragen.']);exit;}
  if(isLocked()){$l=getLock();$now=round(microtime(true)*1000);$m=ceil(($l['until']-$now)/60000);echo json_encode(['ok'=>false,'locked'=>true,'mins'=>$m,'msg'=>"Gesperrt für {$m} Min."]);exit;}
  $pw=$body['pw']??'';$row=getDB()->query("SELECT pw_hash,totp_enabled,totp_secret FROM admin LIMIT 1")->fetch();
  if($row&&password_verify($pw,$row['pw_hash'])){
    setLock(0,0);
    if($row['totp_enabled']&&$row['totp_secret']){$_SESSION['pw_ok']=true;$_SESSION['pw_ok_exp']=time()+120;echo json_encode(['ok'=>true,'needs2fa'=>true]);}
    else{session_regenerate_id(true);$_SESSION['auth']=true;$_SESSION['exp']=time()+1800;logLogin(true,'password');echo json_encode(['ok'=>true,'needs2fa'=>false]);}
  }else{
    $l=getLock();$n=($l['attempts']??0)+1;$u=0;if($n>=5)$u=round(microtime(true)*1000)+15*60000;setLock($n,$u);
    if($n>=10){$ipH=hashIp($_SERVER['REMOTE_ADDR']??'');try{getDB()->prepare("INSERT IGNORE INTO ip_blacklist(ip_hash,reason)VALUES(?,'Auto-ban: 10+ failed logins')")->execute([$ipH]);}catch(Exception $e){}}
    $r=5-min($n,5);logLogin(false,'wrong_pw');
    echo json_encode(['ok'=>false,'locked'=>$n>=5,'msg'=>$n>=5?"⛔ Gesperrt für 15 Min.":"❌ Falsches Passwort — noch {$r} Versuch(e)."]);
  }
  break;

case 'verify_totp':
  if(!rl('totp',5)){echo json_encode(['ok'=>false,'msg'=>'Zu viele Versuche.']);exit;}
  if(empty($_SESSION['pw_ok'])||$_SESSION['pw_ok_exp']<time()){echo json_encode(['ok'=>false,'msg'=>'Session abgelaufen.']);exit;}
  $code=preg_replace('/\D/','',$body['code']??'');$row=getDB()->query("SELECT totp_secret FROM admin LIMIT 1")->fetch();
  if($row&&verTotp($row['totp_secret'],$code)){unset($_SESSION['pw_ok'],$_SESSION['pw_ok_exp']);$_SESSION['auth']=true;$_SESSION['exp']=time()+1800;logLogin(true,'totp');echo json_encode(['ok'=>true]);}
  else{logLogin(false,'wrong_totp');echo json_encode(['ok'=>false,'msg'=>'❌ Falscher Code.']);}
  break;

case 'check': echo json_encode(['ok'=>true,'auth'=>sessOk()]);break;
case 'logout': session_destroy();echo json_encode(['ok'=>true]);break;

case 'change_pw':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $old=$body['old']??'';$new=$body['new']??'';
  if(strlen($new)<8||!preg_match('/[A-Z]/',$new)||!preg_match('/[0-9]/',$new)){echo json_encode(['ok'=>false,'msg'=>'Min. 8 Zeichen + Großbuchstabe + Zahl.']);exit;}
  $row=getDB()->query("SELECT pw_hash FROM admin LIMIT 1")->fetch();
  if(!$row||!password_verify($old,$row['pw_hash'])){echo json_encode(['ok'=>false,'msg'=>'Aktuelles Passwort falsch.']);exit;}
  getDB()->prepare("UPDATE admin SET pw_hash=?")->execute([password_hash($new,PASSWORD_BCRYPT,['cost'=>12])]);
  logActivity('change_pw','Passwort geändert');echo json_encode(['ok'=>true,'msg'=>'✓ Passwort geändert!']);break;

case 'setup_2fa':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $s=newSecret();$_SESSION['pending_totp']=$s;$uri=totpUri($s);
  echo json_encode(['ok'=>true,'secret'=>$s,'qrUrl'=>'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='.urlencode($uri).'&bgcolor=07090e&color=00e5ff']);break;

case 'confirm_2fa':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $code=preg_replace('/\D/','',$body['code']??'');$s=$_SESSION['pending_totp']??'';
  if(!$s){echo json_encode(['ok'=>false,'msg'=>'Kein Setup']);exit;}
  if(verTotp($s,$code)){getDB()->prepare("UPDATE admin SET totp_secret=?,totp_enabled=1")->execute([$s]);unset($_SESSION['pending_totp']);echo json_encode(['ok'=>true,'msg'=>'✓ 2FA aktiviert!']);}
  else echo json_encode(['ok'=>false,'msg'=>'❌ Falscher Code.']);break;

case 'disable_2fa':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $row=getDB()->query("SELECT pw_hash FROM admin LIMIT 1")->fetch();
  if(!$row||!password_verify($body['pw']??'',$row['pw_hash'])){echo json_encode(['ok'=>false,'msg'=>'Passwort falsch.']);exit;}
  getDB()->prepare("UPDATE admin SET totp_secret=NULL,totp_enabled=0")->execute();echo json_encode(['ok'=>true]);break;

case 'get_2fa_status':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $row=getDB()->query("SELECT totp_enabled FROM admin LIMIT 1")->fetch();echo json_encode(['ok'=>true,'enabled'=>(bool)($row['totp_enabled']??false)]);break;

case 'get_login_log':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  echo json_encode(['ok'=>true,'log'=>getDB()->query("SELECT success,reason,created_at FROM login_log ORDER BY id DESC LIMIT 30")->fetchAll()]);break;

case 'get_activity_log':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  echo json_encode(['ok'=>true,'log'=>getDB()->query("SELECT action,detail,created_at FROM activity_log ORDER BY id DESC LIMIT 50")->fetchAll()]);break;

case 'get_profiles':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  echo json_encode(['ok'=>true,'profiles'=>getDB()->query("SELECT slug,name,emoji FROM profiles ORDER BY id ASC")->fetchAll()]);break;

case 'create_profile':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $slug=preg_replace('/[^a-z0-9\-]/','',$body['slug']??'');$name=htmlspecialchars($body['name']??'Neues Profil');
  if(!$slug||strlen($slug)<2){echo json_encode(['ok'=>false,'msg'=>'Ungültiger Slug']);exit;}
  try{getDB()->prepare("INSERT INTO profiles(slug,name,bio,emoji,links,maint_text,cookie_text,footer_text)VALUES(?,?,?,?,?,?,?,?)")->execute([$slug,$name,'','🎬','[]','Wartungsarbeiten...','Keine Cookies.','Made with Scicel Media']);echo json_encode(['ok'=>true,'slug'=>$slug]);}
  catch(Exception $e){echo json_encode(['ok'=>false,'msg'=>'Slug bereits vergeben']);}break;

case 'delete_profile':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $slug=$body['slug']??'';if($slug==='main'){echo json_encode(['ok'=>false,'msg'=>'Hauptprofil kann nicht gelöscht werden']);exit;}
  getDB()->prepare("DELETE FROM profiles WHERE slug=?")->execute([$slug]);echo json_encode(['ok'=>true]);break;

case 'get_settings':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $p=getProfile($body['slug']??'main');if(!$p){echo json_encode(['ok'=>false,'msg'=>'Nicht gefunden']);exit;}
  echo json_encode(['ok'=>true,'profile'=>$p]);break;

case 'save_settings':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $slug=$body['slug']??'main';$links=$body['links']??[];
  foreach($links as &$l){
    $l['url']=filter_var($l['url']??'',FILTER_SANITIZE_URL);
    $l['label']=htmlspecialchars($l['label']??'');
    $l['label_en']=htmlspecialchars($l['label_en']??'');
    if(!empty($l['pw_plain'])){$l['pw_hash']=password_hash($l['pw_plain'],PASSWORD_BCRYPT);unset($l['pw_plain']);}else unset($l['pw_plain']);
    foreach(['badge','video','thumb','countdown','ab_variant','ab_label','starts','expires','geo_block']as $f)$l[$f]=$l[$f]??'';
    $l['reactions_enabled']=isset($l['reactions_enabled'])&&$l['reactions_enabled']?true:false;
  }
  $body['links']=$links;saveProfile($slug,$body);logActivity('save_settings','Profil: '.$slug);echo json_encode(['ok'=>true]);break;

case 'get_public':
  if(!rl('public',60)){echo json_encode(['ok'=>false,'msg'=>'Zu viele Anfragen']);exit;}
  $slug=$body['slug']??'main';$p=getProfile($slug);if(!$p){echo json_encode(['ok'=>false,'msg'=>'Nicht gefunden']);exit;}
  try{getDB()->prepare("INSERT INTO visitor_stats(visit_date,count)VALUES(?,1)ON DUPLICATE KEY UPDATE count=count+1")->execute([date('Y-m-d')]);}catch(Exception $e){}
  $pl=array_map(function($l){
    $ab=null;if(($l['ab_variant']??'')==='ab')$ab=rand(0,1)?'b':'a';
    return['emoji'=>$l['emoji']??'🔗','label'=>$l['label']??'','label_en'=>$l['label_en']??'','url'=>$l['url']??'',
      'color'=>$l['color']??'','protected'=>!empty($l['protected']),'expires'=>$l['expires']??'',
      'badge'=>$l['badge']??'','video'=>$l['video']??'','thumb'=>$l['thumb']??'','countdown'=>$l['countdown']??'',
      'ab_variant'=>$ab,'ab_label'=>$l['ab_label']??'','geo_block'=>$l['geo_block']??'',
      'reactions_enabled'=>$l['reactions_enabled']??true];
  },$p['links']);
  echo json_encode(['ok'=>true,'name'=>$p['name'],'bio'=>$p['bio'],'emoji'=>$p['emoji'],
    'logoUrl'=>$p['logo_url'],'avatarUrl'=>$p['avatar_url'],'avatarAnimated'=>(bool)$p['avatar_animated'],
    'faviconUrl'=>$p['favicon_url'],'color1'=>$p['color1'],'color2'=>$p['color2'],'fontFamily'=>$p['font_family']??'DM Sans',
    'bgImage'=>$p['bg_image'],'bgParticles'=>(bool)$p['bg_particles'],'particleStyle'=>$p['particle_style']??'stars',
    'nameAnimated'=>(bool)($p['name_animated']??0),'ogTitle'=>$p['og_title'],'ogDesc'=>$p['og_desc'],
    'pageTitle'=>$p['page_title']??$p['name'],'footerText'=>$p['footer_text']??'Made with Scicel Media',
    'footerVisible'=>(bool)($p['footer_visible']??1),'ambientSound'=>$p['ambient_sound']??'',
    'langEnabled'=>(bool)($p['lang_enabled']??0),
    'announceEnabled'=>(bool)($p['announce_enabled']??0),'announceText'=>$p['announce_text']??'',
    'announceStyle'=>$p['announce_style']??'accent','announceVersion'=>md5(($p['announce_text']??'').($p['announce_style']??'')),
    'twitchEnabled'=>(bool)($p['twitch_enabled']??0),'twitchUsername'=>htmlspecialchars($p['twitch_username']??''),'milestoneEnabled'=>(bool)($p['milestone_enabled']??0),'milestoneTitle'=>htmlspecialchars($p['milestone_title']??''),'milestoneCurrent'=>(int)($p['milestone_current']??0),'milestoneTarget'=>(int)($p['milestone_target']??1000),'milestoneUnit'=>htmlspecialchars($p['milestone_unit']??'Member'),
    'spotifyEnabled'=>(bool)($p['spotify_enabled']??0),'spotifyClientId'=>$p['spotify_client_id']??'',
    'spotifySecret'=>$p['spotify_client_secret']??'','spotifyRefreshToken'=>$p['spotify_refresh_token']??'',
    'impName'=>$p['imp_name']??'','impAddress'=>$p['imp_address']??'','impEmail'=>$p['imp_email']??'',
    'impPhone'=>$p['imp_phone']??'','impVat'=>$p['imp_vat']??'','impExtra'=>$p['imp_extra']??'',
    'webhookEnabled'=>(bool)($p['webhook_enabled']??0),'webhookUrl'=>$p['webhook_url']??'',
    'avatarFilter'=>$p['avatar_filter']??'filter-none',
    'links'=>$pl,'maint'=>(bool)$p['maint'],'maintText'=>$p['maint_text'],
    'cookieBanner'=>(bool)($p['cookie_banner']??1),'cookieText'=>$p['cookie_text']??'']);break;

case 'unlock_link':
  $code=$body['code']??'';$idx=(int)($body['idx']??-1);$p=getProfile($body['slug']??'main');
  if(!$p||$idx<0||$idx>=count($p['links'])){echo json_encode(['ok'=>false,'msg'=>'Ungültig']);exit;}
  if(password_verify($code,$p['links'][$idx]['pw_hash']??''))echo json_encode(['ok'=>true,'url'=>$p['links'][$idx]['url']]);
  else echo json_encode(['ok'=>false,'msg'=>'Falscher Code']);break;

case 'track_click':
  if(!rl('click')){echo json_encode(['ok'=>false]);exit;}
  $label=htmlspecialchars($body['label']??'');$url=filter_var($body['url']??'',FILTER_SANITIZE_URL);
  if($label&&$url)getDB()->prepare("INSERT INTO link_clicks(link_label,link_url,ip_hash)VALUES(?,?,?)")->execute([$label,$url,hashIp($_SERVER['REMOTE_ADDR']??'')]);
  echo json_encode(['ok'=>true]);break;

case 'track_ab':
  if(!rl('ab',30)){echo json_encode(['ok'=>false]);exit;}
  $label=htmlspecialchars(substr($body['label']??'',0,255));$variant=$body['variant']??'a';
  $url=filter_var($body['url']??'',FILTER_SANITIZE_URL);$slug2=htmlspecialchars($body['slug']??'main');
  $v=$variant==='b'?'b':'a';
  getDB()->prepare("INSERT INTO ab_clicks(slug,label,variant,url,ip_hash)VALUES(?,?,?,?,?)")->execute([$slug2,$label,$v,$url,hashIp($_SERVER['REMOTE_ADDR']??'')]);
  getDB()->prepare("INSERT INTO link_clicks(link_label,link_url,ip_hash)VALUES(?,?,?)")->execute([$label.' ['.$v.']',$url,hashIp($_SERVER['REMOTE_ADDR']??'')]);
  echo json_encode(['ok'=>true]);break;

case 'track_visit':
  if(!rl('visit')){echo json_encode(['ok'=>false]);exit;}
  $src=htmlspecialchars(substr($body['source']??'direct',0,100));$med=htmlspecialchars(substr($body['medium']??'',0,100));
  $cam=htmlspecialchars(substr($body['campaign']??'',0,100));$ref=htmlspecialchars(substr($body['referrer']??'',0,200));
  try{getDB()->prepare("INSERT INTO utm_stats(visit_date,source,medium,campaign,referrer,count)VALUES(?,?,?,?,?,1)ON DUPLICATE KEY UPDATE count=count+1")->execute([date('Y-m-d'),$src,$med,$cam,$ref]);}catch(Exception $e){}
  echo json_encode(['ok'=>true]);break;

case 'track_device':
  if(!rl('dev')){echo json_encode(['ok'=>false]);exit;}
  $ua=$_SERVER['HTTP_USER_AGENT']??'';$type='desktop';
  if(preg_match('/Mobile|Android|iPhone|iPad/i',$ua))$type=preg_match('/iPad/i',$ua)?'tablet':'mobile';
  $country=htmlspecialchars(substr($body['country']??'',0,10));$hour=(int)date('G');
  try{getDB()->prepare("INSERT INTO device_stats(visit_date,device_type,hour,country,count)VALUES(?,?,?,?,1)ON DUPLICATE KEY UPDATE count=count+1")->execute([date('Y-m-d'),$type,$hour,$country]);}catch(Exception $e){}
  echo json_encode(['ok'=>true]);break;

case 'heartbeat':
  if(!rl('hb',20)){echo json_encode(['ok'=>false]);exit;}
  $slug2=htmlspecialchars($body['slug']??'main');$ipH=hashIp($_SERVER['REMOTE_ADDR']??'');
  try{getDB()->prepare("INSERT INTO live_visitors(slug,ip_hash,last_seen)VALUES(?,?,NOW())ON DUPLICATE KEY UPDATE last_seen=NOW()")->execute([$slug2,$ipH]);
  getDB()->exec("DELETE FROM live_visitors WHERE last_seen < DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
  $s3=getDB()->prepare("SELECT COUNT(*) FROM live_visitors WHERE slug=?");$s3->execute([$slug2]);
  echo json_encode(['ok'=>true,'count'=>(int)$s3->fetchColumn()]);}catch(Exception $e){echo json_encode(['ok'=>true,'count'=>1]);}break;

case 'toggle_reaction':
  if(!rl('react',30)){echo json_encode(['ok'=>false]);exit;}
  $slug2=htmlspecialchars($body['slug']??'main');$lbl=htmlspecialchars(substr($body['label']??'',0,255));
  $rx=htmlspecialchars(substr($body['reaction']??'',0,20));$ipH=hashIp($_SERVER['REMOTE_ADDR']??'');
  if(!in_array($rx,['🔥','❤️','😂','🎉','💯'])){echo json_encode(['ok'=>false]);exit;}
  $chk=getDB()->prepare("SELECT id FROM link_reactions WHERE slug=? AND link_label=? AND reaction=? AND ip_hash=?");$chk->execute([$slug2,$lbl,$rx,$ipH]);
  if($chk->fetch()){getDB()->prepare("DELETE FROM link_reactions WHERE slug=? AND link_label=? AND reaction=? AND ip_hash=?")->execute([$slug2,$lbl,$rx,$ipH]);echo json_encode(['ok'=>true,'action'=>'removed']);}
  else{getDB()->prepare("INSERT INTO link_reactions(slug,link_label,reaction,ip_hash)VALUES(?,?,?,?)")->execute([$slug2,$lbl,$rx,$ipH]);echo json_encode(['ok'=>true,'action'=>'added']);}break;

case 'get_reactions':
  $slug2=htmlspecialchars($body['slug']??'main');$ipH=hashIp($_SERVER['REMOTE_ADDR']??'');
  $rows=getDB()->prepare("SELECT link_label,reaction,COUNT(*) as cnt FROM link_reactions WHERE slug=? GROUP BY link_label,reaction");$rows->execute([$slug2]);
  $mine=getDB()->prepare("SELECT link_label,reaction FROM link_reactions WHERE slug=? AND ip_hash=?");$mine->execute([$slug2,$ipH]);
  echo json_encode(['ok'=>true,'reactions'=>$rows->fetchAll(),'mine'=>$mine->fetchAll()]);break;

case 'get_stats':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $db=getDB();
  $vis=$db->query("SELECT visit_date,count FROM visitor_stats ORDER BY visit_date DESC LIMIT 14")->fetchAll();
  $tv=$db->query("SELECT SUM(count) FROM visitor_stats")->fetchColumn();
  $cl=$db->query("SELECT link_label,COUNT(*) as clicks FROM link_clicks GROUP BY link_label ORDER BY clicks DESC")->fetchAll();
  $tc=$db->query("SELECT COUNT(*) FROM link_clicks")->fetchColumn();
  $td=$db->query("SELECT COALESCE(count,0) FROM visitor_stats WHERE visit_date='".date('Y-m-d')."'")->fetchColumn();
  $utm=$db->query("SELECT source,SUM(count) as total FROM utm_stats GROUP BY source ORDER BY total DESC LIMIT 10")->fetchAll();
  $ab=$db->query("SELECT label,variant,COUNT(*) as clicks FROM ab_clicks GROUP BY label,variant ORDER BY label,variant")->fetchAll();
  echo json_encode(['ok'=>true,'visitors'=>array_reverse($vis),'totalVisitors'=>(int)$tv,'todayVisitors'=>(int)$td,'clicks'=>$cl,'totalClicks'=>(int)$tc,'utm'=>$utm,'ab'=>$ab]);break;

case 'get_device_stats':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $devs=getDB()->query("SELECT device_type,SUM(count) as total FROM device_stats GROUP BY device_type")->fetchAll();
  $hours=getDB()->query("SELECT hour,SUM(count) as total FROM device_stats GROUP BY hour ORDER BY hour")->fetchAll();
  $countries=getDB()->query("SELECT country,SUM(count) as total FROM device_stats WHERE country!='' GROUP BY country ORDER BY total DESC LIMIT 10")->fetchAll();
  echo json_encode(['ok'=>true,'devices'=>$devs,'hours'=>$hours,'countries'=>$countries]);break;

case 'get_blacklist':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  echo json_encode(['ok'=>true,'list'=>getDB()->query("SELECT id,ip_hash,reason,created FROM ip_blacklist ORDER BY id DESC LIMIT 50")->fetchAll()]);break;

case 'add_blacklist':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $ip2=hashIp(trim($body['ip']??''));$reason=htmlspecialchars(substr($body['reason']??'Manual ban',0,200));
  try{getDB()->prepare("INSERT INTO ip_blacklist(ip_hash,reason)VALUES(?,?)")->execute([$ip2,$reason]);echo json_encode(['ok'=>true,'msg'=>'IP gesperrt.']);}
  catch(Exception $e){echo json_encode(['ok'=>false,'msg'=>'Bereits gesperrt']);}break;

case 'remove_blacklist':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  getDB()->prepare("DELETE FROM ip_blacklist WHERE id=?")->execute([(int)($body['id']??0)]);echo json_encode(['ok'=>true]);break;

case 'export_backup':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $db=getDB();$profs=$db->query("SELECT * FROM profiles")->fetchAll();
  foreach($profs as &$pr){$pr['links']=json_decode($pr['links']??'[]',true)??[];}
  echo json_encode(['ok'=>true,'data'=>['version'=>'v8','exported_at'=>date('c'),'profiles'=>$profs,
    'visitor_stats'=>$db->query("SELECT * FROM visitor_stats ORDER BY visit_date DESC LIMIT 90")->fetchAll(),
    'link_clicks'=>$db->query("SELECT * FROM link_clicks ORDER BY clicked_at DESC LIMIT 500")->fetchAll()]]);break;

case 'import_backup':
  verifyCsrf($body['csrf']??'');
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $data=$body['data']??null;if(!$data||!isset($data['profiles'])){echo json_encode(['ok'=>false,'msg'=>'Ungültige Backup-Datei']);exit;}
  $db=getDB();$imported=0;
  foreach($data['profiles']??[]as $pr){
    $lj=json_encode($pr['links']??[],JSON_UNESCAPED_UNICODE);
    try{$db->prepare("INSERT INTO profiles(slug,name,bio,emoji,links,color1,color2,font_family,footer_text)VALUES(?,?,?,?,?,?,?,?,?)ON DUPLICATE KEY UPDATE name=VALUES(name),links=VALUES(links),bio=VALUES(bio),color1=VALUES(color1),color2=VALUES(color2)")
      ->execute([$pr['slug'],$pr['name']??'',$pr['bio']??'',$pr['emoji']??'🎬',$lj,$pr['color1']??'#00e5ff',$pr['color2']??'#7b5cff',$pr['font_family']??'DM Sans',$pr['footer_text']??'Made with Scicel Media']);$imported++;}
    catch(Exception $e){}
  }
  echo json_encode(['ok'=>true,'msg'=>"$imported Profile importiert."]);break;

case 'request_pw_reset':
  if(!rl('reset',3)){echo json_encode(['ok'=>false,'msg'=>'Zu viele Anfragen']);exit;}
  $email=filter_var($body['email']??'',FILTER_SANITIZE_EMAIL);
  $token=bin2hex(random_bytes(32));
  getDB()->prepare("INSERT INTO pw_reset(token,expires)VALUES(?,?)")->execute([$token,time()+3600]);
  $link='https://'.$_SERVER['HTTP_HOST'].'/?reset='.$token;
  @mail($email,'Passwort zurücksetzen — Scicel Media',"Link:\n$link\n\nGültig 1 Stunde.","From: noreply@".$_SERVER['HTTP_HOST']);
  logActivity('pw_reset_request','Email: '.$email);echo json_encode(['ok'=>true,'msg'=>'Reset-Link gesendet.']);break;

case 'do_pw_reset':
  $token=preg_replace('/[^a-f0-9]/','',$body['token']??'');$newpw=$body['pw']??'';
  if(strlen($newpw)<8){echo json_encode(['ok'=>false,'msg'=>'Min. 8 Zeichen']);exit;}
  $row=getDB()->prepare("SELECT id,expires,used FROM pw_reset WHERE token=?");$row->execute([$token]);$rt=$row->fetch();
  if(!$rt||$rt['used']||$rt['expires']<time()){echo json_encode(['ok'=>false,'msg'=>'Token ungültig oder abgelaufen']);exit;}
  getDB()->prepare("UPDATE admin SET pw_hash=?")->execute([password_hash($newpw,PASSWORD_BCRYPT,['cost'=>12])]);
  getDB()->prepare("UPDATE pw_reset SET used=1 WHERE token=?")->execute([$token]);
  logActivity('pw_reset_done','Passwort zurückgesetzt');echo json_encode(['ok'=>true,'msg'=>'✓ Passwort geändert!']);break;

case 'upload_image':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $type=$_POST['type']??'bg';$file=$_FILES['image']??null;
  if(!$file||$file['error']!==UPLOAD_ERR_OK){echo json_encode(['ok'=>false,'msg'=>'Upload fehlgeschlagen']);exit;}
  $fi=finfo_open(FILEINFO_MIME_TYPE);$mime=finfo_file($fi,$file['tmp_name']);finfo_close($fi);
  if(!in_array($mime,['image/jpeg','image/png','image/webp','image/gif'])){echo json_encode(['ok'=>false,'msg'=>'Nur JPG/PNG/WEBP/GIF']);exit;}
  if($file['size']>5*1024*1024){echo json_encode(['ok'=>false,'msg'=>'Max. 5MB']);exit;}
  $ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','image/gif'=>'gif'][$mime];
  $fn=$type.'_'.time().'_'.bin2hex(random_bytes(4)).'.'.$ext;$dir=__DIR__.'/uploads/';
  if(!is_dir($dir))mkdir($dir,0755,true);
  if(!file_exists($dir.'.htaccess'))file_put_contents($dir.'.htaccess',"Options -Indexes\n<FilesMatch '\\.php$'>\nDeny from all\n</FilesMatch>");
  if(move_uploaded_file($file['tmp_name'],$dir.$fn))echo json_encode(['ok'=>true,'url'=>'uploads/'.$fn]);
  else echo json_encode(['ok'=>false,'msg'=>'Fehler beim Speichern']);break;

case 'upload_audio':
  if(!sessOk()){echo json_encode(['ok'=>false,'msg'=>'Nicht eingeloggt']);exit;}
  $file=$_FILES['audio']??null;if(!$file||$file['error']!==UPLOAD_ERR_OK){echo json_encode(['ok'=>false,'msg'=>'Upload fehlgeschlagen']);exit;}
  if($file['size']>10*1024*1024){echo json_encode(['ok'=>false,'msg'=>'Max. 10MB']);exit;}
  $ext=strtolower(pathinfo($file['name'],PATHINFO_EXTENSION));if(!in_array($ext,['mp3','ogg','wav'])){echo json_encode(['ok'=>false,'msg'=>'Nur MP3/OGG/WAV']);exit;}
  $fn='audio_'.time().'_'.bin2hex(random_bytes(4)).'.'.$ext;$dir=__DIR__.'/uploads/';if(!is_dir($dir))mkdir($dir,0755,true);
  if(move_uploaded_file($file['tmp_name'],$dir.$fn))echo json_encode(['ok'=>true,'url'=>'uploads/'.$fn]);
  else echo json_encode(['ok'=>false,'msg'=>'Fehler']);break;


case 'twitch_live':
  // Server-side Twitch API proxy - client secret never reaches browser
  $slug2=htmlspecialchars($body['slug']??'main');
  $p2=getProfile($slug2);
  if(!$p2||!$p2['twitch_enabled']||empty($p2['twitch_client_id'])||empty($p2['twitch_client_secret'])||empty($p2['twitch_username'])){
    echo json_encode(['ok'=>false,'live'=>false]);break;
  }
  // Get app access token
  $ctx=stream_context_create(['http'=>['method'=>'POST','header'=>'Content-Type: application/x-www-form-urlencoded',
    'content'=>'client_id='.urlencode($p2['twitch_client_id']).'&client_secret='.urlencode($p2['twitch_client_secret']).'&grant_type=client_credentials','timeout'=>5]]);
  $tokRes=@file_get_contents('https://id.twitch.tv/oauth2/token',false,$ctx);
  if(!$tokRes){echo json_encode(['ok'=>false,'live'=>false]);break;}
  $tok=json_decode($tokRes,true);
  if(empty($tok['access_token'])){echo json_encode(['ok'=>false,'live'=>false]);break;}
  // Check if stream is live
  $ctx2=stream_context_create(['http'=>['method'=>'GET',
    'header'=>'Client-ID: '.$p2['twitch_client_id']."
Authorization: Bearer ".$tok['access_token'],'timeout'=>5]]);
  $streamRes=@file_get_contents('https://api.twitch.tv/helix/streams?user_login='.urlencode($p2['twitch_username']),false,$ctx2);
  if(!$streamRes){echo json_encode(['ok'=>false,'live'=>false]);break;}
  $stream=json_decode($streamRes,true);
  if(empty($stream['data'][0])){echo json_encode(['ok'=>true,'live'=>false]);break;}
  $s=$stream['data'][0];
  echo json_encode(['ok'=>true,'live'=>true,
    'title'=>htmlspecialchars($s['title']??''),
    'game'=>htmlspecialchars($s['game_name']??''),
    'viewers'=>(int)($s['viewer_count']??0)]);break;

case 'spotify_now_playing':
  // Server-side Spotify proxy - credentials never leave server
  $slug3=htmlspecialchars($body['slug']??'main');
  $p3=getProfile($slug3);
  if(!$p3||!$p3['spotify_enabled']||empty($p3['spotify_client_secret'])||empty($p3['spotify_refresh_token'])){
    echo json_encode(['ok'=>false,'playing'=>false]);break;
  }
  // Get access token via refresh token
  $authB64=base64_encode($p3['spotify_client_id'].':'.$p3['spotify_client_secret']);
  $ctx=stream_context_create(['http'=>['method'=>'POST','header'=>"Authorization: Basic $authB64
Content-Type: application/x-www-form-urlencoded",'content'=>'grant_type=refresh_token&refresh_token='.urlencode($p3['spotify_refresh_token']),'timeout'=>5]]);
  $tokRes=@file_get_contents('https://accounts.spotify.com/api/token',false,$ctx);
  if(!$tokRes){echo json_encode(['ok'=>false,'playing'=>false]);break;}
  $tok=json_decode($tokRes,true);
  if(empty($tok['access_token'])){echo json_encode(['ok'=>false,'playing'=>false]);break;}
  // Get now playing
  $ctx2=stream_context_create(['http'=>['method'=>'GET','header'=>'Authorization: Bearer '.$tok['access_token'],'timeout'=>5]]);
  $npRes=@file_get_contents('https://api.spotify.com/v1/me/player/currently-playing',false,$ctx2);
  if(!$npRes||strlen($npRes)<10){echo json_encode(['ok'=>true,'playing'=>false]);break;}
  $np=json_decode($npRes,true);
  if(empty($np['item'])){echo json_encode(['ok'=>true,'playing'=>false]);break;}
  echo json_encode(['ok'=>true,'playing'=>true,
    'track'=>htmlspecialchars($np['item']['name']??''),
    'artist'=>htmlspecialchars($np['item']['artists'][0]['name']??''),
    'albumArt'=>$np['item']['album']['images'][1]['url']??'',
    'duration'=>$np['item']['duration_ms']??0,
    'progress'=>$np['progress_ms']??0]);break;


case 'check_update':
  if(!sessOk())die(json_encode(['ok'=>false]));
  $vc=@file_get_contents(UPDATE_URL.'version.json');
  if(!$vc){echo json_encode(['ok'=>false,'msg'=>'GitHub nicht erreichbar. Netzwerk prüfen.']);break;}
  $vd=json_decode($vc,true);
  if(!$vd||empty($vd['version'])){echo json_encode(['ok'=>false,'msg'=>'Ungültige Versions-Datei.']);break;}
  $remote=trim($vd['version']);$local=APP_VERSION;
  $newer=version_compare($remote,$local,'>');
  echo json_encode(['ok'=>true,'current'=>$local,'remote'=>$remote,'newer'=>$newer,
    'changelog'=>$vd['changelog']??[],'releaseDate'=>$vd['date']??'']);break;

case 'do_update':
  if(!sessOk())die(json_encode(['ok'=>false]));
  verifyCsrf($body['csrf']??'');
  // Check writable
  $self=__FILE__;$idx=dirname(__FILE__).'/index.html';
  if(!is_writable($self)||!is_writable($idx)){
    echo json_encode(['ok'=>false,'msg'=>'Dateien nicht beschreibbar. Bitte Zugriffsrechte prüfen (chmod 644).']);break;
  }
  // Fetch new files
  $newPhp=@file_get_contents(UPDATE_URL.'admin.php');
  $newHtml=@file_get_contents(UPDATE_URL.'index.html');
  if(!$newPhp||!$newHtml||strlen($newPhp)<10000||strlen($newHtml)<50000){
    echo json_encode(['ok'=>false,'msg'=>'Download fehlgeschlagen. Bitte später erneut versuchen.']);break;
  }
  // Safety: verify downloaded files look valid
  if(strpos($newPhp,'<?php')!==0||strpos($newPhp,'APP_VERSION')===false){
    echo json_encode(['ok'=>false,'msg'=>'Ungültige admin.php heruntergeladen. Abgebrochen.']);break;
  }
  if(strpos($newHtml,'<!DOCTYPE html>')===false||strpos($newHtml,'admin.php')===false){
    echo json_encode(['ok'=>false,'msg'=>'Ungültige index.html heruntergeladen. Abgebrochen.']);break;
  }
  // Extract current DB credentials from running file
  preg_match("/define\('DB_HOST','([^']+)'\)/",file_get_contents($self),$mh);
  preg_match("/define\('DB_NAME','([^']+)'\)/",file_get_contents($self),$mn);
  preg_match("/define\('DB_USER','([^']+)'\)/",file_get_contents($self),$mu);
  preg_match("/define\('DB_PASS','([^']+)'\)/",file_get_contents($self),$mp);
  if(empty($mh[1])||empty($mn[1])){
    echo json_encode(['ok'=>false,'msg'=>'DB-Zugangsdaten konnten nicht gelesen werden.']);break;
  }
  // Inject credentials into new file
  $newPhp=preg_replace("/define\('DB_HOST','[^']*'\)/","define('DB_HOST','".$mh[1]."')",$newPhp);
  $newPhp=preg_replace("/define\('DB_NAME','[^']*'\)/","define('DB_NAME','".$mn[1]."')",$newPhp);
  $newPhp=preg_replace("/define\('DB_USER','[^']*'\)/","define('DB_USER','".$mu[1]."')",$newPhp);
  $newPhp=preg_replace("/define\('DB_PASS','[^']*'\)/","define('DB_PASS','".$mp[1]."')",$newPhp);
  // Backup old files
  $ts=date('Ymd_His');
  @copy($self,$self.'.bak.'.$ts);
  @copy($idx,$idx.'.bak.'.$ts);
  // Write new files atomically
  $tmpPhp=$self.'.tmp';$tmpHtml=$idx.'.tmp';
  if(!file_put_contents($tmpPhp,$newPhp)||!file_put_contents($tmpHtml,$newHtml)){
    @unlink($tmpPhp);@unlink($tmpHtml);
    echo json_encode(['ok'=>false,'msg'=>'Schreibfehler. Speicherplatz prüfen.']);break;
  }
  if(!rename($tmpPhp,$self)||!rename($tmpHtml,$idx)){
    @unlink($tmpPhp);@unlink($tmpHtml);
    echo json_encode(['ok'=>false,'msg'=>'Datei konnte nicht ersetzt werden.']);break;
  }
  logActivity('update','Updated to '.APP_VERSION);
  echo json_encode(['ok'=>true,'msg'=>'Update erfolgreich! Seite wird neu geladen...']);break;

case 'rollback_update':
  if(!sessOk())die(json_encode(['ok'=>false]));
  verifyCsrf($body['csrf']??'');
  $self=__FILE__;
  // Find most recent backup
  $baks=glob($self.'.bak.*');
  if(!$baks){echo json_encode(['ok'=>false,'msg'=>'Kein Backup gefunden.']);break;}
  rsort($baks);$latest=$baks[0];
  if(!copy($latest,$self)){echo json_encode(['ok'=>false,'msg'=>'Rollback fehlgeschlagen.']);break;}
  logActivity('rollback','Rolled back from backup');
  echo json_encode(['ok'=>true,'msg'=>'Rollback erfolgreich!']);break;

default: http_response_code(400);echo json_encode(['ok'=>false,'msg'=>'Unbekannte Aktion']);}
