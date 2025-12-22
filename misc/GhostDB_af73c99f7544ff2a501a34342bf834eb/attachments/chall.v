import crypto.rand
import datatypes
import encoding.hex
import json
import math
import os
import readline
import time

struct Row {
	pk string
mut:
	data       string
	created_at i64
}

fn (a Row) == (b Row) bool {
	return a.pk == b.pk
}

fn (a Row) < (b Row) bool {
	return a.pk < b.pk
}

struct Quota {
mut:
	query  u32
	insert u32
	delete u32
}

const free_quota_limits = Quota{
	query:  u32(0) - 1
	insert: 60000
	delete: 1
}

const pro_quota_limits = Quota{
	query:  u32(0) - 1
	insert: u32(0) - 1
	delete: u32(0) - 1
}

const version = 'v0.114.514'

fn print_banner() {
	println('/=============================================================\\')
	println('‖                     .-.                                     ‖')
	println('‖                    (o o)       GhostDB                      ‖')
	println('‖                    | O |      ${version}                    ‖')
	println('‖                     \\   \\      Welcome!                     ‖')
	println('‖                      `~~~`                                  ‖')
	println('\\=============================================================/')
}

fn print_menu_and_quota(quota Quota) {
	println('1. Query Row')
	println('2. Insert Row')
	println('3. Delete Row')
	println('4. Claim Flag')
	println('5. Upgrade to Pro')
	println('6. Show Menu & Quota')
	println('7. Quit')
	println('Current Quota - Query: ${quota.query}, Insert: ${quota.insert}, Delete: ${quota.delete}')
}

fn input(prompt string) string {
	return readline.read_line('<GhostDB> ${prompt}') or { '' }
}

fn query_row(db datatypes.BSTree[Row], mut quota Quota) {
	// It's a shame that vlib makes method `datatypes.BSTree[T].get_node` private,
	// so there's currently no easy way to implement this efficiently.
	if quota.query > 0 {
		quota.query -= 1
		pk := input('Enter primary key to query: ')
		if !db.contains(Row{pk, '', 0}) {
			println('Row not found.')
			return
		}
		rows := db.in_order_traversal()
		mut left := 0
		mut right := rows.len - 1
		for left <= right {
			mid := (left + right) / 2
			if rows[mid].pk == pk {
				println(json.encode_pretty(rows[mid]))
				break
			} else if rows[mid].pk < pk {
				left = mid + 1
			} else {
				right = mid - 1
			}
		}
	} else {
		println('Query quota exceeded.')
	}
}

fn insert_row(mut db datatypes.BSTree[Row], mut quota Quota) {
	bulk := input('Do you want to bulk insert rows? (y/[n]): ')
	mut rows := []Row{}
	if bulk == 'y' {
		json_array := input('Enter JSON array of rows to insert: ')
		if json_array.len > 2000000 {
			println('JSON array too large.')
			return
		}
		rows = json.decode([]Row, json_array) or {
			println('Invalid JSON data.')
			return
		}
	} else {
		pk := input('Enter primary key: ')
		data := input('Enter data: ')
		rows << Row{pk, data, 0}
	}
	if quota.insert >= u32(rows.len) {
		quota.insert -= u32(rows.len)
		mut cnt := 0
		for mut row in rows {
			row.created_at = time.now().unix()
			if db.insert(row) {
				cnt++
			}
		}
		print('${cnt} row(s) inserted.')
		if rows.len - cnt > 0 {
			println('${rows.len - cnt} row(s) failed due to duplicate primary keys.')
		} else {
			println('')
		}
	} else {
		println('Insert quota exceeded.')
	}
}

fn delete_row(mut db datatypes.BSTree[Row], mut quota Quota) {
	if quota.delete > 0 {
		quota.delete -= 1
		pk := input('Enter primary key to delete: ')
		if pk == '@version' {
			println('Cannot delete version row.')
			return
		}
		row := Row{pk, '', 0}
		if db.remove(row) {
			println('Row deleted.')
		} else {
			println('Row not found.')
		}
	} else {
		println('Delete quota exceeded.')
	}
}

fn claim_flag(affected_rows int) {
	if affected_rows > 114514 {
		flag := os.read_file('flag') or { 'fake{flag}' }
		println('Congratulations! Here is your flag: ${flag}')
	} else {
		println('Sorry, you need to affect more than 114514 rows to claim the flag.')
	}
}

fn upgrade_to_pro(mut quota Quota) {
	license_key := input('Enter license key: ')
	if license_key == hex.encode(rand.bytes(128) or {
		println('Invalid license key.')
		return
	}) {
		quota = pro_quota_limits
		println('Upgraded to Pro.')
	} else {
		println('Invalid license key.')
	}
}

fn main() {
	print_banner()
	mut db := datatypes.BSTree[Row]{}
	db.insert(Row{'@version', 'GhostDB ${version}', 0})
	mut quota := free_quota_limits
	mut affected_rows := 0
	print_menu_and_quota(quota)
	for {
		rows := db.in_order_traversal().len
		choice := input('Choose an action: ')
		match choice {
			'1' {
				query_row(db, mut quota)
			}
			'2' {
				insert_row(mut db, mut quota)
			}
			'3' {
				delete_row(mut db, mut quota)
			}
			'4' {
				claim_flag(affected_rows)
			}
			'5' {
				upgrade_to_pro(mut quota)
			}
			'6' {
				print_menu_and_quota(quota)
			}
			'7' {
				println('Bye!')
				break
			}
			else {
				println('Invalid action. Enter 6 to show menu & quota.')
			}
		}
		affected_rows += math.abs(db.in_order_traversal().len - rows)
	}
}
