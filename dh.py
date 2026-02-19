"""
Протокол Диффи-Хеллмана, атака на слабые параметры, сравнение производительности.
"""

import secrets
import time
from sympy import isprime, factorint, nextprime


def generate_safe_prime(bits: int) -> int:
    """Генерация safe prime p = 2q + 1."""
    while True:
        q = nextprime(secrets.randbits(bits - 1))
        p = 2 * q + 1  # type: ignore
        if isprime(p) and p.bit_length() >= bits:
            return p


def generate_weak_prime(bits: int, small_factor: int = 0) -> tuple[int, int]:
    """Генерация простого p, у которого (p-1) делится на малый простой q."""
    if small_factor == 0:
        small_factor = nextprime(secrets.randbelow(50) + 10)  # type: ignore

    base = 1 << (bits - 1)
    k_start = base // small_factor
    for k in range(k_start, k_start + 500_000):
        p = k * small_factor + 1
        if p.bit_length() >= bits and isprime(p):
            return p, small_factor

    raise RuntimeError(f"Не удалось найти слабое простое (bits={bits})")


def find_generator(p: int) -> int:
    """Поиск генератора группы Z_p*."""
    factors = factorint(p - 1)
    for g in range(2, p):
        if all(pow(g, (p - 1) // q, p) != 1 for q in factors):
            return g
    raise RuntimeError("Генератор не найден")


def validate_params(p: int, g: int) -> bool:
    """Проверка корректности параметров DH."""
    if not isprime(p):
        return False
    if g < 2 or g >= p:
        return False
    if pow(g, p - 1, p) != 1:
        return False
    return True


class DHParty:
    """Участник протокола DH."""

    def __init__(self, name: str, p: int, g: int):
        self.name = name
        self.p = p
        self.g = g
        self.private_key = secrets.randbelow(p - 2) + 1
        self.public_key = pow(g, self.private_key, p)
        self.shared_secret = None

    def compute_shared_secret(self, other_public: int) -> int:
        """Вычисление общего секрета K = other_public^a mod p."""
        self.shared_secret = pow(other_public, self.private_key, self.p)
        return self.shared_secret


def run_dh(p: int, g: int) -> tuple[DHParty, DHParty]:
    """Запуск DH между Alice и Bob."""
    alice = DHParty("Alice", p, g)
    bob = DHParty("Bob", p, g)
    alice.compute_shared_secret(bob.public_key)
    bob.compute_shared_secret(alice.public_key)
    return alice, bob


def small_subgroup_attack(p: int, g: int, public_key: int, small_factor: int) -> int:
    """Восстановление секретного ключа mod small_factor через малую подгруппу."""
    exp = (p - 1) // small_factor
    A_proj = pow(public_key, exp, p)
    g_proj = pow(g, exp, p)

    for x in range(small_factor):
        if pow(g_proj, x, p) == A_proj:
            return x

    raise RuntimeError("Атака не удалась")


def benchmark_dh(bits: int, label: str):
    """Замер времени DH для заданного размера p."""
    print(f"\n{label} (p ~ 2^{bits})")
    print("=" * 40)

    t0 = time.perf_counter()
    p = generate_safe_prime(bits)
    g = find_generator(p)
    t_params = time.perf_counter() - t0
    print(f"Генерация параметров: {t_params:.4f} с")
    print(f"p = {p}")
    print(f"g = {g}")

    t0 = time.perf_counter()
    alice, bob = run_dh(p, g)
    t_dh = time.perf_counter() - t0

    match = alice.shared_secret == bob.shared_secret
    print(f"DH обмен: {t_dh:.6f} с")
    print(f"Секреты совпадают: {'Да' if match else 'Нет'}")

    return t_params, t_dh


def main():
    print("ПРОТОКОЛ ДИФФИ-ХЕЛЛМАНА: демонстрация и анализ")
    print("=" * 50)

    print("\n1. Базовый протокол Диффи-Хеллмана")
    print("-" * 40)

    p = generate_safe_prime(64)
    g = find_generator(p)
    print(f"p = {p} (safe prime, {p.bit_length()} бит)")
    print(f"g = {g}")

    assert validate_params(p, g), "Параметры невалидны!"
    print("Параметры прошли проверку.")

    alice, bob = run_dh(p, g)
    print(f"\nAlice:")
    print(f"  Секретный ключ a = {alice.private_key}")
    print(f"  Публичный ключ A = g^a mod p = {alice.public_key}")
    print(f"Bob:")
    print(f"  Секретный ключ b = {bob.private_key}")
    print(f"  Публичный ключ B = g^b mod p = {bob.public_key}")
    print(f"\nОбщий секрет Alice: K = B^a mod p = {alice.shared_secret}")
    print(f"Общий секрет Bob:   K = A^b mod p = {bob.shared_secret}")
    print(f"Секреты совпадают: {'Да' if alice.shared_secret == bob.shared_secret else 'Нет'}")

    print("\n\n2. Атака на слабые параметры (Small Subgroup Attack)")
    print("-" * 40)

    weak_p, small_q = generate_weak_prime(64, small_factor=23)
    weak_g = find_generator(weak_p)
    print(f"Слабое простое p = {weak_p} ({weak_p.bit_length()} бит)")
    print(f"Малый делитель (p-1): q = {small_q}")
    print(f"Генератор g = {weak_g}")

    alice_w = DHParty("Alice", weak_p, weak_g)
    print(f"\nAlice (жертва):")
    print(f"  Секретный ключ a = {alice_w.private_key}")
    print(f"  Публичный ключ A = {alice_w.public_key}")

    t0 = time.perf_counter()
    recovered = small_subgroup_attack(weak_p, weak_g, alice_w.public_key, small_q)
    t_attack = time.perf_counter() - t0

    actual_mod = alice_w.private_key % small_q
    print(f"\nРезультат атаки:")
    print(f"  Восстановлено: a = {recovered} (mod {small_q})")
    print(f"  Реальное:      a = {actual_mod} (mod {small_q})")
    print(f"  Атака {'успешна' if recovered == actual_mod else 'провалилась'}!")
    print(f"  Время атаки: {t_attack:.6f} с")

    print(f"\nЗная a mod {small_q}, атакующий получает частичную информацию")
    print(f"о секретном ключе. Чем больше малых делителей у (p-1), тем больше")
    print(f"информации утекает (CRT позволяет комбинировать остатки).")

    print("\n\n3. Сравнение производительности")
    print("-" * 40)

    t_params_32, t_dh_32 = benchmark_dh(32, "Малое p")
    t_params_1024, t_dh_1024 = benchmark_dh(1024, "Большое p (рекомендуемое)")

    print(f"\n\nИтоговая сводка")
    print("=" * 50)
    print(f"{'Параметр':<30} {'p~2^32':>12} {'p~2^1024':>12} {'Разница':>10}")
    print(f"{'Генерация параметров (с)':<30} {t_params_32:>12.4f} {t_params_1024:>12.4f} {t_params_1024/max(t_params_32, 1e-9):>9.1f}x")
    print(f"{'DH обмен (с)':<30} {t_dh_32:>12.6f} {t_dh_1024:>12.6f} {t_dh_1024/max(t_dh_32, 1e-9):>9.1f}x")

    print(f"\nУвеличение размера p значительно влияет на время генерации")
    print(f"параметров, но обеспечивает криптографическую стойкость.")
    print(f"p ~ 2^1024 — минимально рекомендуемый размер для реального применения.")


if __name__ == "__main__":
    main()
