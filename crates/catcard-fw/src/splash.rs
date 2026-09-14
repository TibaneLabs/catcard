//! Drawing the boot splash on this board's panel.

use catcard_ui::splash;

use crate::{VERSION, display};

/// Redraw the splash at `progress` percent.
///
/// The framebuffer is rebuilt each time rather than kept around: it is a kilobyte, this
/// runs half a dozen times at boot, and a splash that shares state with whatever draws
/// next is a source of debris on screen.
pub fn show(panel: &mut display::Panel, progress: u8) {
    // A failed flush is not worth stopping the boot for -- the device is still usable
    // through SWD and USB, and the next screen tries again.
    display::draw(panel, |c| splash::draw(c, VERSION, progress));
}
