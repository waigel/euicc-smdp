/// euicc-rsp's failure convention, kept apart rather than flattened.
///
/// `include/rsp.h` argues for this split at every declaration that has
/// it: `-1` means the question was asked and the answer is no, `-2`
/// means the question was never reached. They call for different
/// responses -- reject-and-move-on versus report-and-stop -- and the
/// ES9+ JSON binding needs the difference too, since a refusal and an
/// internal failure produce different function execution statuses.
///
/// A `Result` that collapsed both into one error would throw away
/// exactly what that library was careful to provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RspError {
    /// `-1`: asked, answered no.
    Refused(&'static str),
    /// `-2`: never reached.
    NotReached(&'static str),
}

impl std::fmt::Display for RspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RspError::Refused(w) => write!(f, "{w}: refused"),
            RspError::NotReached(w) => write!(f, "{w}: could not be attempted"),
        }
    }
}

impl std::error::Error for RspError {}

impl RspError {
    /// The library returns only 0, -1 and -2. Mapping anything
    /// unexpected to the more cautious of the two beats asserting.
    pub(crate) fn from_code(code: i32, what: &'static str) -> Self {
        if code == -1 {
            RspError::Refused(what)
        } else {
            RspError::NotReached(what)
        }
    }
}

pub type Result<T> = std::result::Result<T, RspError>;
