use std::{error::Error, path::Path};

use serde::Deserialize;

use crate::{atomic_write, option};

const SVG_WIDTH: f64 = 960.0;
const SVG_HEIGHT: f64 = 540.0;
const LEFT: f64 = 90.0;
const RIGHT: f64 = 40.0;
const TOP: f64 = 40.0;
const BOTTOM: f64 = 100.0;
const CHANGE_THRESHOLD_PERCENT: f64 = 5.0;

#[derive(Debug)]
struct Point {
    report: String,
    timestamp: String,
    throughput: f64,
}

#[derive(Debug, Deserialize)]
struct PerformanceArtifact {
    drift: PerformanceDrift,
}

#[derive(Debug, Deserialize)]
struct PerformanceDrift {
    median_throughput_per_second: f64,
}

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let directory = Path::new(option(arguments, "--dir")?);
    if !directory.is_dir() {
        return Err(format!("trends directory does not exist: {}", directory.display()).into());
    }
    let mut points = discover(directory).await?;
    if points.len() < 2 {
        return Err(
            "trends requires at least two named report roots containing controlled performance evidence"
                .into(),
        );
    }
    points.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.report.cmp(&right.report))
    });
    let svg = render_svg(&points);
    atomic_write(&directory.join("throughput.svg"), svg.as_bytes()).await?;
    let markdown = render_markdown(&points);
    atomic_write(&directory.join("TRENDS.md"), markdown.as_bytes()).await
}

async fn discover(directory: &Path) -> Result<Vec<Point>, Box<dyn Error>> {
    let mut points = Vec::new();
    let mut entries = tokio::fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let report = entry.file_name().to_string_lossy().into_owned();
        let Some(timestamp) = report_timestamp(&report) else {
            continue;
        };
        let timestamp = timestamp.to_owned();
        let artifact_path = entry
            .path()
            .join("performance-controlled")
            .join("performance.json");
        let Ok(bytes) = tokio::fs::read(&artifact_path).await else {
            continue;
        };
        let artifact: PerformanceArtifact = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "invalid controlled performance artifact {}: {error}",
                artifact_path.display()
            )
        })?;
        let throughput = artifact.drift.median_throughput_per_second;
        if !throughput.is_finite() || throughput <= 0.0 {
            return Err(format!(
                "controlled throughput must be finite and positive in {}",
                artifact_path.display()
            )
            .into());
        }
        points.push(Point {
            report,
            timestamp,
            throughput,
        });
    }
    Ok(points)
}

fn report_timestamp(name: &str) -> Option<&str> {
    let (sha, timestamp) = name.rsplit_once('-')?;
    let sha_valid = (7..=40).contains(&sha.len())
        && sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    let timestamp_shape = timestamp.len() == 16
        && timestamp.as_bytes().get(8) == Some(&b'T')
        && timestamp.as_bytes().get(15) == Some(&b'Z')
        && timestamp
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 15) || byte.is_ascii_digit());
    (sha_valid && timestamp_shape && valid_timestamp(timestamp)).then_some(timestamp)
}

fn valid_timestamp(timestamp: &str) -> bool {
    let parse = |range: std::ops::Range<usize>| timestamp[range].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0..4),
        parse(4..6),
        parse(6..8),
        parse(9..11),
        parse(11..13),
        parse(13..15),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

fn render_svg(points: &[Point]) -> String {
    let plot_width = SVG_WIDTH - LEFT - RIGHT;
    let plot_height = SVG_HEIGHT - TOP - BOTTOM;
    let minimum = points
        .iter()
        .map(|point| point.throughput)
        .fold(f64::INFINITY, f64::min);
    let maximum = points
        .iter()
        .map(|point| point.throughput)
        .fold(f64::NEG_INFINITY, f64::max);
    let padding = if maximum > minimum {
        (maximum - minimum) * 0.1
    } else {
        (maximum * 0.05).max(1.0)
    };
    let lower = (minimum - padding).max(0.0);
    let upper = maximum + padding;
    let x = |index: usize| LEFT + plot_width * index as f64 / (points.len() - 1) as f64;
    let y = |throughput: f64| TOP + (upper - throughput) * plot_height / (upper - lower);
    let coordinates = points
        .iter()
        .enumerate()
        .map(|(index, point)| format!("{:.2},{:.2}", x(index), y(point.throughput)))
        .collect::<Vec<_>>()
        .join(" ");

    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{SVG_WIDTH}\" height=\"{SVG_HEIGHT}\" viewBox=\"0 0 {SVG_WIDTH} {SVG_HEIGHT}\" role=\"img\" aria-labelledby=\"title description\">\n\
         <title id=\"title\">pg-proto controlled throughput trend</title>\n\
         <desc id=\"description\">Median controlled throughput for each historical burn-in report.</desc>\n\
         <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n\
         <line x1=\"{LEFT}\" y1=\"{TOP}\" x2=\"{LEFT}\" y2=\"{}\" stroke=\"#334155\" stroke-width=\"2\"/>\n\
         <line x1=\"{LEFT}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#334155\" stroke-width=\"2\"/>\n",
        TOP + plot_height,
        TOP + plot_height,
        LEFT + plot_width,
        TOP + plot_height,
    );
    for tick in 0..=4 {
        let value = lower + (upper - lower) * tick as f64 / 4.0;
        let tick_y = y(value);
        svg.push_str(&format!(
            "<line x1=\"{LEFT}\" y1=\"{tick_y:.2}\" x2=\"{}\" y2=\"{tick_y:.2}\" stroke=\"#e2e8f0\"/>\n\
             <text x=\"{}\" y=\"{:.2}\" text-anchor=\"end\" font-family=\"sans-serif\" font-size=\"12\" fill=\"#475569\">{value:.2}</text>\n",
            LEFT + plot_width,
            LEFT - 10.0,
            tick_y + 4.0,
        ));
    }
    svg.push_str(&format!(
        "<polyline points=\"{coordinates}\" fill=\"none\" stroke=\"#2563eb\" stroke-width=\"3\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n"
    ));
    for (index, point) in points.iter().enumerate() {
        svg.push_str(&format!(
            "<circle cx=\"{:.2}\" cy=\"{:.2}\" r=\"5\" fill=\"#2563eb\"><title>{}: {:.2} operations/s</title></circle>\n",
            x(index),
            y(point.throughput),
            point.report,
            point.throughput,
        ));
    }
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"16\" fill=\"#0f172a\">report</text>\n\
         <text x=\"20\" y=\"{}\" text-anchor=\"middle\" transform=\"rotate(-90 20 {})\" font-family=\"sans-serif\" font-size=\"16\" fill=\"#0f172a\">throughput</text>\n\
         </svg>\n",
        LEFT + plot_width / 2.0,
        SVG_HEIGHT - 20.0,
        TOP + plot_height / 2.0,
        TOP + plot_height / 2.0,
    ));
    svg
}

fn render_markdown(points: &[Point]) -> String {
    let first = points.first().expect("at least two trend points");
    let latest = points.last().expect("at least two trend points");
    let change = (latest.throughput - first.throughput) * 100.0 / first.throughput;
    let disposition = if change > CHANGE_THRESHOLD_PERCENT {
        "performance improved"
    } else if change < -CHANGE_THRESHOLD_PERCENT {
        "performance regressed"
    } else {
        "performance holding"
    };
    let mut markdown = format!(
        "# Performance trends\n\n![Throughput trend](throughput.svg)\n\n## Summary\n\n**{disposition}**: controlled median throughput changed from {:.2} to {:.2} operations/s ({change:+.2}%) across {} reports. Changes within ±{CHANGE_THRESHOLD_PERCENT:.0}% are classified as holding.\n\n## Reports\n\n| Report | Throughput (operations/s) |\n| --- | ---: |\n",
        first.throughput,
        latest.throughput,
        points.len(),
    );
    for point in points {
        markdown.push_str(&format!(
            "| [{}]({}/performance-controlled/performance.json) | {:.2} |\n",
            point.report, point.report, point.throughput
        ));
    }
    markdown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_root_name_requires_lowercase_git_sha_and_basic_utc_timestamp() {
        assert_eq!(
            report_timestamp("04776f4-20260817T143000Z"),
            Some("20260817T143000Z")
        );
        for invalid in [
            "manual-20260817T143000Z",
            "04776F4-20260817T143000Z",
            "04776f4-2026-08-17T14:30:00Z",
            "04776f-20260817T143000Z",
            "04776f4-20261317T143000Z",
            "04776f4-20260229T143000Z",
        ] {
            assert_eq!(report_timestamp(invalid), None, "accepted {invalid}");
        }
    }
}
