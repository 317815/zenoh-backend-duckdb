/* Copyright (C) 2025-2035 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * Contributors:
 * - Zhenjun <zhenjun@netprism.org>
 *
 * This is a backend for Zenoh using DuckDB.
 */

fn main() {
    // Add rustc version to zenohd
    let version_meta = rustc_version::version_meta().unwrap();
    println!(
        "cargo:rustc-env=RUSTC_VERSION={}",
        version_meta.short_version_string
    );
}
