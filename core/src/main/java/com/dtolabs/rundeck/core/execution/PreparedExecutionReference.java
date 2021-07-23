package com.dtolabs.rundeck.core.execution;

import com.dtolabs.rundeck.core.jobs.JobReference;

/**
 * Details about an execution that has no state
 */
public interface PreparedExecutionReference {
    /**
     * @return project name
     */
    String getProject();

    /**
     * @return execution ID
     */
    String getId();

    /**
     * @return job reference, or null if not associated with a job
     */
    JobReference getJob();

    /**
     * @return true if execution was created from a schedule trigger
     */
    boolean isScheduled();

    /**
     * @return execution type
     */
    String getExecutionType();
}
