-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Oct 22, 2025 at 06:45 AM
-- Server version: 8.0.30
-- PHP Version: 8.3.20

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `network_monitoring`
--

-- --------------------------------------------------------

--
-- Table structure for table `devices`
--

CREATE TABLE `devices` (
  `id` int NOT NULL,
  `name` varchar(100) NOT NULL,
  `ip_address` varchar(50) NOT NULL,
  `description` text,
  `status` enum('online','offline','unknown') DEFAULT 'unknown',
  `last_check` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `devices`
--

INSERT INTO `devices` (`id`, `name`, `ip_address`, `description`, `status`, `last_check`, `created_at`) VALUES
(7, ' Google DNS Primary', '8.8.8.8', '', 'online', '2025-10-22 13:14:28', '2025-10-22 06:07:50'),
(8, 'Telkom Indonesia', '202.152.0.2', '', 'online', '2025-10-22 13:14:31', '2025-10-22 06:09:22'),
(10, 'laptop', '192.168.1.1', '', 'online', '2025-10-22 13:14:34', '2025-10-22 06:14:19');

-- --------------------------------------------------------

--
-- Table structure for table `monitoring_logs`
--

CREATE TABLE `monitoring_logs` (
  `id` int NOT NULL,
  `device_id` int NOT NULL,
  `status` enum('online','offline') NOT NULL,
  `latency` decimal(10,2) DEFAULT '0.00',
  `packet_loss` decimal(5,2) DEFAULT '0.00',
  `response_time` int DEFAULT NULL,
  `checked_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `monitoring_logs`
--

INSERT INTO `monitoring_logs` (`id`, `device_id`, `status`, `latency`, `packet_loss`, `response_time`, `checked_at`) VALUES
(31, 7, 'online', 4.00, 0.00, NULL, '2025-10-22 13:08:05'),
(33, 7, 'online', 4.00, 0.00, NULL, '2025-10-22 13:08:12'),
(34, 7, 'online', 3.00, 0.00, NULL, '2025-10-22 13:09:27'),
(35, 8, 'online', 16.00, 0.00, NULL, '2025-10-22 13:09:30'),
(36, 7, 'online', 3.00, 0.00, NULL, '2025-10-22 13:10:13'),
(37, 8, 'online', 16.00, 0.00, NULL, '2025-10-22 13:10:16'),
(39, 7, 'online', 4.00, 0.00, NULL, '2025-10-22 13:14:28'),
(40, 8, 'online', 16.00, 0.00, NULL, '2025-10-22 13:14:31'),
(41, 10, 'online', 1.00, 0.00, NULL, '2025-10-22 13:14:34');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','viewer') DEFAULT 'viewer',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `created_at`) VALUES
(1, 'admin', 'admin@example.com', 'scrypt:32768:8:1$NEj1P4r5H3yQAY3O$bbe1a14a3e36b821fb9e685439bbcebbdb97478ba303b7e468e80cd61085464e1794be79ccbd9506228ef468a7d401f736b92ffa6c1c65ab03342a2e0328362c', 'admin', '2025-10-22 05:03:04'),
(2, 'viewer', 'viewer@example.com', 'scrypt:32768:8:1$MHfeCsLUIAmBkbGp$fe312e241d1f88dec3d7bea610bbb094b3ae2330213ed7b440be262611775d56044e0ef896047c0accc5f21e32b458bde77606933e52f362bb1885ada5b12e1a', 'viewer', '2025-10-22 05:03:04');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `devices`
--
ALTER TABLE `devices`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `monitoring_logs`
--
ALTER TABLE `monitoring_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_device_time` (`device_id`,`checked_at`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `devices`
--
ALTER TABLE `devices`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `monitoring_logs`
--
ALTER TABLE `monitoring_logs`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=42;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `monitoring_logs`
--
ALTER TABLE `monitoring_logs`
  ADD CONSTRAINT `monitoring_logs_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
