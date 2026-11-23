package pool

import "time"

// AgeProjectInfo makes the cached project info look older than it is, so a
// test can reach the "stale copy" state without waiting out the TTL.
func (m *Manager) AgeProjectInfo(projectID string, by time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.infos[projectID]; ok {
		entry.createdAt = entry.createdAt.Add(-by)
	}
}

// ForgetProjectInfo drops the cached project info, the "never read" state.
func (m *Manager) ForgetProjectInfo(projectID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.infos, projectID)
}
