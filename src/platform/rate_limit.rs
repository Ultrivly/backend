


use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after_secs: u64 },
}



pub async fn check(
    pool: &PgPool,
    key: &str,
    limit: i32,
    window: Duration,
) -> sqlx::Result<Decision> {
    let (count, retry_after): (i32, f64) = sqlx::query_as(
        "INSERT INTO rate_limits AS r (key, window_start, count)
         VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), 1)
         ON CONFLICT (key, window_start) DO UPDATE SET count = r.count + 1
         RETURNING count, extract(epoch FROM window_start + make_interval(secs => $2) - now())::float8",
    )
    .bind(key)
    .bind(window.as_secs_f64())
    .fetch_one(pool)
    .await?;
    Ok(if count <= limit {
        Decision::Allowed
    } else {
        Decision::Limited {
            retry_after_secs: retry_after.ceil().max(1.0) as u64,
        }
    })
}


pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

pub async fn delete_old_windows(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM rate_limits WHERE window_start < now() - interval '1 day'")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::ip_key;

    #[test]
    fn groups_ipv6_by_64() {
        assert_eq!(ip_key("203.0.113.9".parse().unwrap()), "203.0.113.9");
        assert_eq!(
            ip_key("2001:db8:1:2:aaaa::1".parse().unwrap()),
            ip_key("2001:db8:1:2:bbbb::2".parse().unwrap())
        );
        assert_eq!(ip_key("::ffff:203.0.113.9".parse().unwrap()), "203.0.113.9");
    }
}
