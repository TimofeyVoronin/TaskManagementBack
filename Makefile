# Makefile

.PHONY: up migrate down dump backup

##  Поднять все сервисы (с пересборкой образов) в фоне
up:
	docker compose up --build

##  Накатить миграции внутри запущенного контейнера Django
migrate:
	docker compose exec django python manage.py migrate

##  Остановить и удалить контейнеры
down:
	docker compose down

## Сделать дамп БД в backups/dump.sql
dump:
	@mkdir -p backups
	@echo "Создаю дамп БД в backups/dump.sql…"
	@docker compose exec db sh -c 'pg_dump -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -F p' \
		> backups/dump.sql
	@echo "Готово."

## Восстановить БД из backups/dump.sql
backup:
	@test -f backups/dump.sql || (echo "Файл backups/dump.sql не найден"; exit 1)
	@echo "Восстанавливаю БД из backups/dump.sql…"
	@docker compose exec db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -f /backups/dump.sql'
	@echo "Готово."