create database if not exists  cve;

CREATE TABLE IF NOT EXISTS cve.`msf_module` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `fullname` VARCHAR(150) COLLATE utf8mb4_bin NOT NULL COMMENT '模块全路径(如exploit/windows/smb/ms17_010_eternalblue)',
  `module_type` ENUM('exploit','auxiliary','payload','post','encoder','nop') NOT NULL COMMENT '模块类型',
  `service` VARCHAR(50) COLLATE utf8mb4_bin COMMENT '关联服务(如smb,http,ssh)',
  `protocol` ENUM('tcp','udp','http','https','smb','ftp') DEFAULT NULL COMMENT '协议类型',
  `platform` ENUM('windows','linux','android','unix','osx','multi') DEFAULT NULL COMMENT '目标平台',
  `cve_id` VARCHAR(20) COMMENT '关联CVE编号',
  `rank` ENUM('excellent','great','good','normal','average','low','manual') COMMENT '模块可靠性评级',
  `disclosure_date` DATE COMMENT '漏洞公开日期',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_fullname` (`fullname`),
  KEY `idx_cve` (`cve_id`),
  KEY `idx_module_type` (`module_type`),
  CONSTRAINT `fk_vuln` FOREIGN KEY (`cve_id`)
    REFERENCES `vulnerabilities` (`cve_id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Metasploit框架模块表';


CREATE TABLE if not exists cve.`vulnerabilities` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `cve_id` VARCHAR(20) NOT NULL COMMENT 'CVE标准编号',
  `vuln_name` VARCHAR(255) NOT NULL COMMENT '漏洞名称',
  `discovery_date` DATE NOT NULL COMMENT '发现日期',
  `disclosure_date` DATE COMMENT '公开日期',
  `severity` ENUM('Critical','High','Medium','Low') NOT NULL COMMENT '严重等级',
  `cvss_score` DECIMAL(3,1) UNSIGNED COMMENT 'CVSS评分',
  `affected_versions` TEXT COMMENT '受影响版本范围',
  `vuln_type` VARCHAR(50) NOT NULL COMMENT '漏洞类型(SQLi/XSS等)',
  `description` TEXT NOT NULL COMMENT '漏洞描述',
  `poc_code` LONGTEXT COMMENT '验证代码',
  `solution` TEXT NOT NULL COMMENT '修复方案',
  `reference_urls` JSON COMMENT '参考链接',
  `is_zero_day` BOOLEAN DEFAULT FALSE COMMENT '是否零日漏洞',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_cve` (`cve_id`),
  KEY `idx_severity` (`severity`),
  KEY `idx_date` (`discovery_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='漏洞详情主表';
