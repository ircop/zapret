-- phpMyAdmin SQL Dump
-- version 3.3.8.1
-- http://www.phpmyadmin.net
--
-- Хост: localhost
-- Время создания: Авг 02 2014 г., 02:23
-- Версия сервера: 5.1.51
-- Версия PHP: 5.3.3-pl1-gentoo

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- База данных: `tech`
--

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_domains`
--

CREATE TABLE IF NOT EXISTS `zap2_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `domain` varchar(60) NOT NULL,
  `domain_fixed` varchar(60) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1448 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_ex_domains`
--

CREATE TABLE IF NOT EXISTS `zap2_ex_domains` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_ex_ips`
--

CREATE TABLE IF NOT EXISTS `zap2_ex_ips` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `ip` int(12) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip` (`ip`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_ex_nets`
--

CREATE TABLE IF NOT EXISTS `zap2_ex_nets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `subnet` (`subnet`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_ips`
--

CREATE TABLE IF NOT EXISTS `zap2_ips` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `record_id` int(6) unsigned NOT NULL,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` int(12) unsigned NOT NULL,
  `resolved` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2603 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_records`
--

CREATE TABLE IF NOT EXISTS `zap2_records` (
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
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3083 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_settings`
--

CREATE TABLE IF NOT EXISTS `zap2_settings` (
  `param` varchar(255) NOT NULL,
  `value` longtext NOT NULL,
  KEY `param` (`param`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

INSERT INTO `zap2_settings` (`param`, `value`) VALUES
('lastDumpDate', '1406930960'),
('lastAction', 'getResult'),
('lastResult', 'got'),
('lastCode', '25ff77c0d152d7544ba2f72a95cbff50'),
('lastActionDate', '1406929097'),
('lastDump', '<?xml version="1.0" encoding="windows-1251"?>\r\n<reg:register updateTime="2014-02-02T12:00:00+04:00" updateTimeUrgently="2014-02-01T11:00:00" xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru">\r\n<content id="1101" includeTime="2013-12-01T10:00:05">\r\n        <decision date="2013-12-01" number="9" org="');

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_subnets`
--

CREATE TABLE IF NOT EXISTS `zap2_subnets` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `subnet` varchar(30) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Структура таблицы `zap2_urls`
--

CREATE TABLE IF NOT EXISTS `zap2_urls` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `date_add` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `record_id` int(6) unsigned NOT NULL,
  `url` text NOT NULL,
  `url_fixed` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3358 ;

