Как именно включать “жесть”
1) Стандартный режим (жёстко, но без перемешивания)
python cisco_sanitizer.py running-config.txt safe-config.txt
# или
python cisco_sanitizer.py running-config.txt safe-config.txt --mode=standard

2) MAX-паранойя:

всё выше;

плюс:

перемешаны интерфейсы/ACL/маршруты;

добавлены фейковые интерфейсы/ACL/маршруты;

комментарии выпилены;

descriptions, VLAN, ACL names максимально анонимизированы.

python cisco_sanitizer.py running-config.txt safe-config.txt --max
# или
python cisco_sanitizer.py running-config.txt safe-config.txt --mode=max

3) Разные соли для разных проектов

Чтобы один и тот же реальный IP в разных конфигах/проектах мапился в разные фейковые IP:

python cisco_sanitizer.py run_proj1.txt safe_proj1.txt --max --salt=proj1_secret
python cisco_sanitizer.py run_proj2.txt safe_proj2.txt --max --salt=proj2_secret