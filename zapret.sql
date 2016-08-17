-- MySQL dump 10.13  Distrib 5.1.73, for redhat-linux-gnu (x86_64)
--
-- Host: localhost    Database: rkn
-- ------------------------------------------------------
-- Server version	5.1.73

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `zap2_domains`
--

DROP TABLE IF EXISTS `zap2_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `domain` varchar(255) NOT NULL,
  `domain_fixed` varchar(60) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_domains`
--

DROP TABLE IF EXISTS `zap2_ex_domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_ips`
--

DROP TABLE IF EXISTS `zap2_ex_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_ips` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `ip` int(12) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ex_nets`
--

DROP TABLE IF EXISTS `zap2_ex_nets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ex_nets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `subnet` (`subnet`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_ips`
--

DROP TABLE IF EXISTS `zap2_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_ips` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `record_id` int(6) unsigned NOT NULL,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varbinary(16) DEFAULT NULL,
  `resolved` int(1) NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
  KEY `record_id` (`record_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_only_ips`
--

DROP TABLE IF EXISTS `zap2_only_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_only_ips` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `record_id` int(6) unsigned NOT NULL,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varbinary(16) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_records`
--

DROP TABLE IF EXISTS `zap2_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_records` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `decision_id` int(10) unsigned NOT NULL,
  `decision_date` varchar(50) DEFAULT NULL,
  `decision_num` varchar(50) DEFAULT NULL,
  `decision_org` varchar(50) DEFAULT NULL,
  `include_time` varchar(50) DEFAULT NULL,
  `entry_type` int(3) unsigned DEFAULT NULL,
  KEY `id` (`id`),
  KEY `decision_id` (`decision_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_settings`
--

DROP TABLE IF EXISTS `zap2_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_settings` (
  `param` varchar(255) NOT NULL,
  `value` longtext NOT NULL,
  KEY `param` (`param`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

INSERT INTO `zap2_settings` (`param`, `value`) VALUES
('lastDumpDate', '1406930960'),
('lastAction', 'getResult'),
('lastResult', 'got'),
('lastCode', '25ff77c0d152d7544ba2f72a95cbff50'),
('lastActionDate', '1406929097'),
('lastDump', '<?xml version="1.0" encoding="windows-1251"?>\r\n<reg:register updateTime="2014-02-02T12:00:00+04:00" updateTimeUrgently="2014-02-01T11:00:00" xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru">\r\n<content id="1101" includeTime="2013-12-01T10:00:05">\r\n        <decision date="2013-12-01" number="9" org="');

--
-- Table structure for table `zap2_subnets`
--

DROP TABLE IF EXISTS `zap2_subnets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_subnets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `zap2_urls`
--

DROP TABLE IF EXISTS `zap2_urls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `zap2_urls` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `url` text NOT NULL,
  `url_fixed` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-11-30 10:59:07
