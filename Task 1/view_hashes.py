from history import view_all_hashes

rows = view_all_hashes()

print("\nStored Password Hashes in Database:\n")

for row in rows:
    print(f"ID: {row[0]} | Hash: {row[1]}")