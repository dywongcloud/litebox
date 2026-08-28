//! Simple graphics abstraction: soft-rasterizer backend, extensible to GL/Vulkan.
//! Provides basic 2D drawing operations (fill, rect, circle, line, gradient).

use std::sync::{Arc, Mutex};

/// 32-bit RGBA color.
#[derive(Clone, Copy, Debug)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    #[allow(dead_code)]
    pub fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Color { r, g, b, a }
    }

    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Color { r, g, b, a: 255 }
    }

    pub fn as_u32(&self) -> u32 {
        ((self.a as u32) << 24) | ((self.b as u32) << 16) | ((self.g as u32) << 8) | (self.r as u32)
    }

    #[allow(dead_code)]
    pub fn from_u32(val: u32) -> Self {
        Color {
            r: (val & 0xFF) as u8,
            g: ((val >> 8) & 0xFF) as u8,
            b: ((val >> 16) & 0xFF) as u8,
            a: ((val >> 24) & 0xFF) as u8,
        }
    }
}

pub trait Surface: Send {
    fn width(&self) -> u16;
    fn height(&self) -> u16;
    fn clear(&mut self, color: Color);
    fn fill_rect(&mut self, x: u16, y: u16, w: u16, h: u16, color: Color);
    fn fill_circle(&mut self, cx: u16, cy: u16, r: u16, color: Color);
    fn draw_line(&mut self, x0: u16, y0: u16, x1: u16, y1: u16, color: Color, thickness: u8);
    fn horizontal_gradient(&mut self, x: u16, y: u16, w: u16, h: u16, color_left: Color, color_right: Color);
    fn vertical_gradient(&mut self, x: u16, y: u16, w: u16, h: u16, color_top: Color, color_bottom: Color);
    #[allow(dead_code)]
    fn get_pixel(&self, x: u16, y: u16) -> Color;
    #[allow(dead_code)]
    fn set_pixel(&mut self, x: u16, y: u16, color: Color);
    fn as_bytes(&self) -> &[u8];
}

/// Software rasterizer backend: 32bpp RGBA, write-combined optimized.
pub struct SoftRasterizer {
    width: u16,
    height: u16,
    pixels: Vec<u32>,
}

impl SoftRasterizer {
    pub fn new(width: u16, height: u16) -> Self {
        let size = (width as usize) * (height as usize);
        SoftRasterizer {
            width,
            height,
            pixels: vec![0u32; size],
        }
    }

    #[inline]
    fn index(&self, x: u16, y: u16) -> Option<usize> {
        if x < self.width && y < self.height {
            Some((y as usize) * (self.width as usize) + (x as usize))
        } else {
            None
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn blend(&self, dst: u32, src: Color) -> u32 {
        if src.a == 255 {
            src.as_u32()
        } else {
            let dst_c = Color::from_u32(dst);
            let alpha = src.a as u32;
            let inv_alpha = (255u32 - src.a as u32) as u32;
            Color {
                r: (((src.r as u32 * alpha) + (dst_c.r as u32 * inv_alpha)) / 255) as u8,
                g: (((src.g as u32 * alpha) + (dst_c.g as u32 * inv_alpha)) / 255) as u8,
                b: (((src.b as u32 * alpha) + (dst_c.b as u32 * inv_alpha)) / 255) as u8,
                a: 255,
            }
            .as_u32()
        }
    }
}

impl Surface for SoftRasterizer {
    fn width(&self) -> u16 {
        self.width
    }

    fn height(&self) -> u16 {
        self.height
    }

    fn clear(&mut self, color: Color) {
        let val = color.as_u32();
        for pixel in self.pixels.iter_mut() {
            *pixel = val;
        }
    }

    fn fill_rect(&mut self, x: u16, y: u16, w: u16, h: u16, color: Color) {
        let val = color.as_u32();
        let x_max = (x as usize + w as usize).min(self.width as usize);
        let y_max = (y as usize + h as usize).min(self.height as usize);
        let x_min = x as usize;
        let y_min = y as usize;

        if x_min >= x_max || y_min >= y_max {
            return;
        }

        for row in y_min..y_max {
            let row_start = row * (self.width as usize);
            for col in x_min..x_max {
                self.pixels[row_start + col] = val;
            }
        }
    }

    fn fill_circle(&mut self, cx: u16, cy: u16, r: u16, color: Color) {
        let val = color.as_u32();
        let r_sq = (r as i32) * (r as i32);
        let cx = cx as i32;
        let cy = cy as i32;

        for dy in -(r as i32)..=(r as i32) {
            for dx in -(r as i32)..=(r as i32) {
                if dx * dx + dy * dy <= r_sq {
                    let x = (cx + dx) as u16;
                    let y = (cy + dy) as u16;
                    if let Some(idx) = self.index(x, y) {
                        self.pixels[idx] = val;
                    }
                }
            }
        }
    }

    fn draw_line(&mut self, x0: u16, y0: u16, x1: u16, y1: u16, color: Color, thickness: u8) {
        let val = color.as_u32();
        let x0 = x0 as i32;
        let y0 = y0 as i32;
        let x1 = x1 as i32;
        let y1 = y1 as i32;
        let t = thickness as i32;

        let dx = (x1 - x0).abs();
        let dy = (y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx - dy;
        let mut x = x0;
        let mut y = y0;

        loop {
            for ty in -t / 2..=(t / 2 + 1) {
                for tx in -t / 2..=(t / 2 + 1) {
                    let px = (x + tx) as u16;
                    let py = (y + ty) as u16;
                    if let Some(idx) = self.index(px, py) {
                        self.pixels[idx] = val;
                    }
                }
            }

            if x == x1 && y == y1 {
                break;
            }

            let e2 = 2 * err;
            if e2 > -dy {
                err -= dy;
                x += sx;
            }
            if e2 < dx {
                err += dx;
                y += sy;
            }
        }
    }

    fn horizontal_gradient(&mut self, x: u16, y: u16, w: u16, h: u16, color_left: Color, color_right: Color) {
        let x_max = (x as usize + w as usize).min(self.width as usize);
        let y_max = (y as usize + h as usize).min(self.height as usize);
        let x_min = x as usize;
        let y_min = y as usize;

        if x_min >= x_max || y_min >= y_max {
            return;
        }

        let width = (x_max - x_min) as u32;
        for row in y_min..y_max {
            for col in x_min..x_max {
                let t = ((col - x_min) as f32) / (width as f32);
                let r = ((color_left.r as f32) * (1.0 - t) + (color_right.r as f32) * t) as u8;
                let g = ((color_left.g as f32) * (1.0 - t) + (color_right.g as f32) * t) as u8;
                let b = ((color_left.b as f32) * (1.0 - t) + (color_right.b as f32) * t) as u8;
                let color = Color { r, g, b, a: 255 };
                self.pixels[row * (self.width as usize) + col] = color.as_u32();
            }
        }
    }

    fn vertical_gradient(&mut self, x: u16, y: u16, w: u16, h: u16, color_top: Color, color_bottom: Color) {
        let x_max = (x as usize + w as usize).min(self.width as usize);
        let y_max = (y as usize + h as usize).min(self.height as usize);
        let x_min = x as usize;
        let y_min = y as usize;

        if x_min >= x_max || y_min >= y_max {
            return;
        }

        let height = (y_max - y_min) as u32;
        for row in y_min..y_max {
            let t = ((row - y_min) as f32) / (height as f32);
            let r = ((color_top.r as f32) * (1.0 - t) + (color_bottom.r as f32) * t) as u8;
            let g = ((color_top.g as f32) * (1.0 - t) + (color_bottom.g as f32) * t) as u8;
            let b = ((color_top.b as f32) * (1.0 - t) + (color_bottom.b as f32) * t) as u8;
            let color = Color { r, g, b, a: 255 };
            for col in x_min..x_max {
                self.pixels[row * (self.width as usize) + col] = color.as_u32();
            }
        }
    }

    fn get_pixel(&self, x: u16, y: u16) -> Color {
        if let Some(idx) = self.index(x, y) {
            Color::from_u32(self.pixels[idx])
        } else {
            Color::rgb(0, 0, 0)
        }
    }

    fn set_pixel(&mut self, x: u16, y: u16, color: Color) {
        if let Some(idx) = self.index(x, y) {
            self.pixels[idx] = color.as_u32();
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self.pixels.as_ptr() as *const u8;
        let len = self.pixels.len() * 4;
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// Thread-safe graphics context wrapping a Surface.
pub struct Graphics {
    surface: Arc<Mutex<Box<dyn Surface>>>,
}

impl Graphics {
    pub fn new(surface: Box<dyn Surface>) -> Self {
        Graphics {
            surface: Arc::new(Mutex::new(surface)),
        }
    }

    pub fn clear(&self, color: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.clear(color);
        }
    }

    pub fn fill_rect(&self, x: u16, y: u16, w: u16, h: u16, color: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.fill_rect(x, y, w, h, color);
        }
    }

    pub fn fill_circle(&self, cx: u16, cy: u16, r: u16, color: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.fill_circle(cx, cy, r, color);
        }
    }

    pub fn draw_line(&self, x0: u16, y0: u16, x1: u16, y1: u16, color: Color, thickness: u8) {
        if let Ok(mut s) = self.surface.lock() {
            s.draw_line(x0, y0, x1, y1, color, thickness);
        }
    }

    pub fn horizontal_gradient(&self, x: u16, y: u16, w: u16, h: u16, color_left: Color, color_right: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.horizontal_gradient(x, y, w, h, color_left, color_right);
        }
    }

    pub fn vertical_gradient(&self, x: u16, y: u16, w: u16, h: u16, color_top: Color, color_bottom: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.vertical_gradient(x, y, w, h, color_top, color_bottom);
        }
    }

    #[allow(dead_code)]
    pub fn get_pixel(&self, x: u16, y: u16) -> Color {
        if let Ok(s) = self.surface.lock() {
            s.get_pixel(x, y)
        } else {
            Color::rgb(0, 0, 0)
        }
    }

    #[allow(dead_code)]
    pub fn set_pixel(&self, x: u16, y: u16, color: Color) {
        if let Ok(mut s) = self.surface.lock() {
            s.set_pixel(x, y, color);
        }
    }

    pub fn width(&self) -> u16 {
        if let Ok(s) = self.surface.lock() {
            s.width()
        } else {
            0
        }
    }

    pub fn height(&self) -> u16 {
        if let Ok(s) = self.surface.lock() {
            s.height()
        } else {
            0
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        if let Ok(s) = self.surface.lock() {
            s.as_bytes().to_vec()
        } else {
            Vec::new()
        }
    }

    #[allow(dead_code)]
    pub fn clone_arc(&self) -> Arc<Mutex<Box<dyn Surface>>> {
        Arc::clone(&self.surface)
    }
}

impl Clone for Graphics {
    fn clone(&self) -> Self {
        Graphics {
            surface: Arc::clone(&self.surface),
        }
    }
}
