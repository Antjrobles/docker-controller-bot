# Docker Controller Bot - Project Overview

This document provides a summary of the Docker Controller Bot project for AI assistants.

## Project Purpose
A Python-based Telegram bot that serves as a controller for Docker containers. It allows users to manage containers (start, stop, restart, delete, view logs) and perform safe image updates directly from a Telegram chat.

## Architecture

### Core Components
*   **`docker-controller-bot.py`**: The main entry point. Initializes the Telegram bot, starts background monitors (`DockerEventMonitor`, `DockerUpdateMonitor`, `DockerScheduleMonitor`), and handles user commands/callbacks.
*   **`docker_update.py`**: Handles the logic for safely updating containers. It implements a transactional update process (backup config -> stop -> rename -> create new -> verify -> delete old or rollback).
*   **`schedule_manager.py`**: Manages user-defined scheduled tasks (e.g., "restart container X every day at 10:00"). Persists schedules to `schedule/schedules.json` (mapped volume).
*   **`schedule_flow.py`**: Handles the user interaction flow for creating new schedules via Telegram wizard-style dialogs.
*   **`config.py`**: Centralized configuration. Loads environment variables and defines regex patterns and constants.
*   **`migrate_schedules.py`**: A utility script to migrate schedule data formats if necessary.

### Data Persistence
*   **Configuration**: Environment variables (defined in `docker-compose.yaml` / `.env`).
*   **Schedules**: `schedules.json` file stored in the `/app/schedule` volume.
*   **State**: In-memory state for active wizard flows; Pickle-based cache for some temporary data.

### Localization
*   **Mechanism**: JSON files in the `locale/` directory (`en.json`, `es.json`, etc.).
*   **Usage**: The `get_text(key, lang)` function resolves strings based on the `LANGUAGE` environment variable.

## Key Features
*   **Container Management**: List, Start, Stop, Remove containers.
*   **Logs**: Retrieve logs as text or file.
*   **Updates**: Check for image updates, notify users, and perform "safe updates" with rollback on failure.
*   **Scheduling**: Cron-like scheduling for container actions.
*   **Notifications**: Real-time alerts for container events (die, start) and available updates.
*   **Security**: Restricted to specific Telegram User IDs (`TELEGRAM_ADMIN`).

## Development & Deployment
*   **Docker**: The primary deployment method.
*   **CI/CD**: `Dockerfile`, `Dockerfile_local`, and `Dockerfile_debug` exist for different stages.
*   **Debug**: `docker-compose.debug.yaml` and VS Code configuration (`.vscode/launch.json`) support remote debugging inside the container.

## Important Considerations
*   **Socket Access**: Requires mounting `/var/run/docker.sock` to function.
*   **Thread Safety**: Uses locks for file I/O and container updates to prevent race conditions.
*   **Rate Limiting**: Implements a custom `MessageQueue` to respect Telegram API limits.
