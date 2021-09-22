// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Build time variables set through "-ldflags".

/// Monotonic build number, currently based on the date and hour-of-day.
/// It will be set to a build number by the build tools (for 'production' builds for now).
static BuildNumber: String;

/// Git commit id in effect when the build was created.
/// It will be set by the build tools (for 'production' builds for now).
static CommitHash: String;

/// Git branch in effect when the build was created.
/// It will be set by the build tools.
static Branch: String;

/// Computed release channel based on the Branch in effect when the build was created.
/// It will be set by the build tools.
static Channel: String;

/// Default setting to use for EnableDeadlockDetection.
/// It's computed for the build based on the current branch being built
/// - intending to disable deadlock detection in 'production' builds.
static DefaultDeadlock: String;
