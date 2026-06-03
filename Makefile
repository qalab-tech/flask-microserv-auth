.PHONY: up down build logs test test-positive test-negative shell db-shell redis-shell fresh help

# ================== Основные команды ==================

up:
	docker-compose up --build -d

down:
	docker-compose down -v

build:
	docker-compose build --no-cache

logs:
	docker-compose logs -f auth-service

fresh:
	docker-compose down -v && docker-compose up --build -d

# ================== Тесты ==================

test:
	docker-compose exec auth-service pytest tests/ -v --tb=short

test-positive:
	docker-compose exec auth-service pytest tests/test_users_positive_cases.py -v --tb=short

test-negative:
	docker-compose exec auth-service pytest tests/test_users_negative_cases.py -v --tb=short

# ================== Доступ к контейнерам ==================

shell:
	docker-compose exec auth-service bash

# ================== Работа с базами ==================

db-shell:
	docker-compose exec auth-postgres psql -U postgres -d authdb

db-albums:
	docker-compose exec postgres psql -U postgres -d albumsdb

redis-shell:
	docker-compose exec redis redis-cli

# ================== Полезные команды ==================

restart:
	docker-compose restart auth-service

status:
	docker-compose ps

# Полная очистка + запуск
reset:
	docker-compose down -v && docker-compose up --build -d

help:
	@echo "=== Основные команды ==="
	@echo "  make up              - Запустить все сервисы"
	@echo "  make down            - Остановить и удалить контейнеры"
	@echo "  make fresh / reset   - Полная пересборка с нуля"
	@echo ""
	@echo "=== Тесты ==="
	@echo "  make test            - Запустить все тесты"
	@echo "  make test-positive   - Только позитивные тесты"
	@echo "  make test-negative   - Только негативные тесты"
	@echo ""
	@echo "=== Доступ к сервисам ==="
	@echo "  make shell           - Зайти в auth-service (bash)"
	@echo "  make db-shell        - Зайти в psql authdb"
	@echo "  make db-albums       - Зайти в psql albumsdb"
	@echo "  make redis-shell     - Зайти в redis-cli"
	@echo "  make logs            - Посмотреть логи auth-service"
	@echo ""
	@echo "  make help            - Показать эту справку"